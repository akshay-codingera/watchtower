"""
beacon/cartographer.py
=======================
WATCHTOWER — Device Classification

Classifies devices into a DeviceType based on whatever evidence is
available: MAC vendor (OUI), SNMP sysDescr, hostname patterns, and
which syslog format the device has been sending in.

Design principle: classification is best-effort and additive. Every
classify_by_* method returns a DeviceType string or None (unknown).
Cartographer.classify() tries them in order of reliability and takes
the first hit. No single signal is required — a device with only a
hostname can still be classified, just less confidently.

This module has no DB or network dependency — it is pure logic.
herald.py, snmp_probe.py, and arp_scout.py all feed it evidence;
none of them talk to the database directly here.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field

from nucleus.constants import DeviceType, LogFormat

logger = logging.getLogger(__name__)


# ── MAC OUI (first 3 octets) → vendor hints ───────────────────────────────────
# Not exhaustive — covers vendors likely to appear on an NTPC-style
# industrial / AV / network estate. Extend as new devices show up.
# Keys are uppercase, colon-separated, no trailing content (e.g. "00:1A:2B").

_OUI_VENDOR_TYPE: dict[str, str] = {
    "00:1B:D7": DeviceType.CISCO_SWITCH,
    "00:0F:34": DeviceType.CISCO_SWITCH,
    "F4:CF:E2": DeviceType.CISCO_ROUTER,
    "AC:A0:16": DeviceType.HP_SWITCH,
    "94:F1:28": DeviceType.HP_SWITCH,
    "24:DE:C6": DeviceType.UNIFI_AP,
    "FC:EC:DA": DeviceType.UNIFI_AP,
    "18:64:72": DeviceType.ARUBA_AP,
    "94:B4:0F": DeviceType.ARUBA_AP,
    "00:09:0F": DeviceType.FORTINET_FIREWALL,
    "70:4C:A5": DeviceType.PALO_ALTO,
}

# ── Vendor name substrings (from SNMP sysDescr or ARP OUI lookup) ────────────
_VENDOR_KEYWORD_TYPE: list[tuple[str, str]] = [
    ("cisco",     DeviceType.CISCO_SWITCH),
    ("fortinet",  DeviceType.FORTINET_FIREWALL),
    ("fortigate", DeviceType.FORTINET_FIREWALL),
    ("pfsense",   DeviceType.PFSENSE_FIREWALL),
    ("palo alto", DeviceType.PALO_ALTO),
    ("juniper",   DeviceType.JUNIPER),
    ("aruba",     DeviceType.ARUBA_AP),
    ("ubiquiti",  DeviceType.UNIFI_AP),
    ("unifi",     DeviceType.UNIFI_AP),
    ("hewlett",   DeviceType.HP_SWITCH),
    ("hp switch", DeviceType.HP_SWITCH),
    ("windows",   DeviceType.WINDOWS_SERVER),
    ("linux",     DeviceType.LINUX_SERVER),
]

# ── Hostname patterns → device type (regex, case-insensitive) ────────────────
_HOSTNAME_PATTERN_TYPE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bsw-?\d", re.I),      DeviceType.CISCO_SWITCH),
    (re.compile(r"\bswitch", re.I),      DeviceType.CISCO_SWITCH),
    (re.compile(r"\brtr-?\d|\brouter", re.I), DeviceType.CISCO_ROUTER),
    (re.compile(r"\bfw-?\d|firewall", re.I),  DeviceType.FORTINET_FIREWALL),
    (re.compile(r"\bap-?\d", re.I),      DeviceType.ARUBA_AP),
    (re.compile(r"\bcam-?\d|camera", re.I), DeviceType.IP_CAMERA),
    (re.compile(r"\bprinter|\bpr-?\d", re.I), DeviceType.PRINTER),
    (re.compile(r"\bwin-", re.I),        DeviceType.WINDOWS_SERVER),
    (re.compile(r"\bws-?\d", re.I),      DeviceType.WINDOWS_WORKSTATION),
]

# ── Syslog format → device type hint (weak signal, used last) ────────────────
_FORMAT_TYPE_HINT: dict[str, str] = {
    LogFormat.CISCO:    DeviceType.CISCO_SWITCH,
    LogFormat.FORTINET: DeviceType.FORTINET_FIREWALL,
    LogFormat.PFSENSE:  DeviceType.PFSENSE_FIREWALL,
    LogFormat.CEF:      DeviceType.PALO_ALTO,
    LogFormat.WINEVENT:  DeviceType.WINDOWS_SERVER,
}


@dataclass
class ClassificationEvidence:
    """
    Bundle of everything Cartographer might use to classify a device.
    All fields optional — supply whatever you have.
    """
    mac_address: str = ""          # e.g. "00:1B:D7:AA:BB:CC"
    snmp_sysdescr: str = ""        # raw sysDescr.0 string
    hostname: str = ""
    syslog_format: str = ""        # LogFormat value, if known
    open_ports: list[int] = field(default_factory=list)


class Cartographer:
    """
    Stateless device classifier. No DB, no network — pure evidence-in,
    DeviceType-out logic. Safe to instantiate once and reuse everywhere.
    """

    def classify(self, evidence: ClassificationEvidence) -> str:
        """
        Classify a device from the given evidence, trying the most
        reliable signals first.

        Order of trust:
            1. MAC OUI            (hardware-level, very reliable)
            2. SNMP sysDescr      (device self-reports, reliable)
            3. Hostname pattern   (naming convention, medium confidence)
            4. Syslog format      (weak — many devices share a format)

        Args:
            evidence: ClassificationEvidence with whatever signals are known.

        Returns:
            A DeviceType string. DeviceType.UNKNOWN if nothing matched.
        """
        result = self._by_mac_vendor(evidence.mac_address)
        if result:
            return result

        result = self._by_snmp_sysdescr(evidence.snmp_sysdescr)
        if result:
            return result

        result = self._by_hostname(evidence.hostname)
        if result:
            return result

        result = self._by_syslog_format(evidence.syslog_format)
        if result:
            return result

        result = self._by_open_ports(evidence.open_ports)
        if result:
            return result

        return DeviceType.UNKNOWN

    def vendor_from_mac(self, mac_address: str) -> str:
        """
        Best-effort vendor name lookup from a MAC's OUI prefix.
        Returns '' if the OUI is not in the local table.

        For a fuller vendor name (not just a DeviceType hint), extend
        _OUI_VENDOR_TYPE with a proper IEEE OUI database dump when one
        is available — this table intentionally stays small and curated.
        """
        oui = self._normalize_oui(mac_address)
        if oui in _OUI_VENDOR_TYPE:
            return _OUI_VENDOR_TYPE[oui]
        return ""

    # ── Private classifiers ───────────────────────────────────────────────────

    def _by_mac_vendor(self, mac_address: str) -> str:
        if not mac_address:
            return ""
        oui = self._normalize_oui(mac_address)
        return _OUI_VENDOR_TYPE.get(oui, "")

    def _by_snmp_sysdescr(self, sysdescr: str) -> str:
        if not sysdescr:
            return ""
        lowered = sysdescr.lower()
        for keyword, device_type in _VENDOR_KEYWORD_TYPE:
            if keyword in lowered:
                return device_type
        return ""

    def _by_hostname(self, hostname: str) -> str:
        if not hostname:
            return ""
        for pattern, device_type in _HOSTNAME_PATTERN_TYPE:
            if pattern.search(hostname):
                return device_type
        return ""

    def _by_syslog_format(self, syslog_format: str) -> str:
        if not syslog_format:
            return ""
        return _FORMAT_TYPE_HINT.get(syslog_format, "")

    def _by_open_ports(self, open_ports: list[int]) -> str:
        """
        Very weak fallback signal. Only used when nothing else matched.
        161 (SNMP) + 22/23 (SSH/Telnet) with no other evidence suggests
        network gear; 9100/515/631 suggests a printer.
        """
        if not open_ports:
            return ""
        ports = set(open_ports)
        if {9100, 515, 631} & ports:
            return DeviceType.PRINTER
        if 554 in ports:  # RTSP
            return DeviceType.IP_CAMERA
        return ""

    @staticmethod
    def _normalize_oui(mac_address: str) -> str:
        """Extract and normalize the first 3 octets of a MAC address."""
        cleaned = mac_address.upper().replace("-", ":")
        parts = cleaned.split(":")
        if len(parts) < 3:
            return ""
        return ":".join(parts[:3])