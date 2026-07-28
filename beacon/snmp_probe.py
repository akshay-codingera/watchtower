"""
beacon/snmp_probe.py
=====================
WATCHTOWER — SNMP Query Layer

Queries devices via SNMP GET/WALK for uptime, sysDescr, and interface
statistics. This is the layer that lets WATCHTOWER know a switch is
still alive even if it never sends a single syslog line.

Design principle: shell out to the net-snmp command-line tools
(snmpget, snmpwalk, snmpbulkwalk) instead of depending on a Python
SNMP library. net-snmp-utils is present on virtually every Linux
distro's package repos and is what's typically already installed on
NOC-adjacent boxes — this avoids a heavyweight pysnmp/pyasn1
dependency for something the OS can already do.

If net-snmp-utils is not installed, every method here raises SNMPError
with a clear message — install it with:
    apt install snmp        (Debian/Ubuntu)
    yum install net-snmp-utils   (RHEL/CentOS)

SNMPv2c only (community string auth). SNMPv3 is out of scope for now —
add it here if a device on the network requires it.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass

from nucleus.exceptions import SNMPError

logger = logging.getLogger(__name__)

# ── Well-known OIDs ────────────────────────────────────────────────────────────
OID_SYSDESCR   = "1.3.6.1.2.1.1.1.0"
OID_SYSUPTIME  = "1.3.6.1.2.1.1.3.0"
OID_SYSNAME    = "1.3.6.1.2.1.1.5.0"
OID_IF_DESCR   = "1.3.6.1.2.1.2.2.1.2"    # walk — interface names
OID_IF_OPER    = "1.3.6.1.2.1.2.2.1.8"    # walk — 1=up, 2=down
OID_IF_IN_OCT  = "1.3.6.1.2.1.2.2.1.10"   # walk — bytes in
OID_IF_OUT_OCT = "1.3.6.1.2.1.2.2.1.16"   # walk — bytes out

_IF_OPER_STATUS = {"1": "up", "2": "down", "3": "testing", "4": "unknown"}

# `snmpget`/`snmpwalk` output line pattern:
#   iso.3.6.1.2.1.1.1.0 = STRING: "Cisco IOS Software..."
_VALUE_LINE_RE = re.compile(r"^\S+\s*=\s*\w+:\s*(.*)$")
# Walk lines with an index suffix, e.g. "...2.2.1.2.1 = STRING: GigabitEthernet0/1"
_WALK_INDEX_RE = re.compile(r"^\S+\.(\d+)\s*=\s*\w+:\s*(.*)$")


@dataclass
class InterfaceStats:
    index: str
    name: str = ""
    status: str = "unknown"
    in_octets: int = 0
    out_octets: int = 0


class SNMPProbe:
    """
    SNMPv2c query interface via net-snmp CLI tools.

    Args:
        community: SNMP community string (default 'public').
        timeout:   Per-request timeout in seconds.
        retries:   Number of retries on timeout.
    """

    def __init__(self, community: str = "public", timeout: int = 2, retries: int = 1) -> None:
        self._community = community
        self._timeout   = timeout
        self._retries   = retries
        self._binaries_checked = False

    def get(self, ip: str, oid: str) -> str:
        """
        SNMP GET a single OID from a device.

        Args:
            ip:  Target device IP.
            oid: Numeric OID string (e.g. '1.3.6.1.2.1.1.1.0').

        Returns:
            The value as a string (quotes stripped).

        Raises:
            SNMPError: If the tool is missing, the device doesn't
                       respond, or the OID is invalid.
        """
        self._require_binary("snmpget")
        cmd = self._base_cmd("snmpget", ip) + [oid]
        output = self._run(cmd, ip, oid)
        return self._parse_single_value(output)

    def walk(self, ip: str, oid: str) -> dict[str, str]:
        """
        SNMP WALK a subtree, returning every leaf under the given OID.

        Args:
            ip:  Target device IP.
            oid: Base OID to walk.

        Returns:
            Dict mapping the trailing index (e.g. interface number)
            to its value string.

        Raises:
            SNMPError: If the tool is missing or the walk fails.
        """
        self._require_binary("snmpwalk")
        cmd = self._base_cmd("snmpwalk", ip) + [oid]
        output = self._run(cmd, ip, oid)
        return self._parse_walk(output)

    def get_sysdescr(self, ip: str) -> str:
        """Fetch the device's sysDescr.0 — a free-text self-identification string."""
        return self.get(ip, OID_SYSDESCR)

    def get_uptime_ticks(self, ip: str) -> int:
        """
        Fetch sysUpTime.0 in centiseconds (SNMP TimeTicks unit).
        Divide by 100 for seconds.
        """
        raw = self.get(ip, OID_SYSUPTIME)
        digits = re.findall(r"\d+", raw)
        return int(digits[0]) if digits else 0

    def get_interfaces(self, ip: str) -> list[InterfaceStats]:
        """
        Fetch a combined interface table: name, oper status, and byte
        counters, joined by interface index.

        Args:
            ip: Target device IP.

        Returns:
            List of InterfaceStats, one per interface.

        Raises:
            SNMPError: If any of the underlying walks fail.
        """
        names   = self.walk(ip, OID_IF_DESCR)
        status  = self.walk(ip, OID_IF_OPER)
        in_oct  = self.walk(ip, OID_IF_IN_OCT)
        out_oct = self.walk(ip, OID_IF_OUT_OCT)

        interfaces: list[InterfaceStats] = []
        for idx, name in names.items():
            interfaces.append(InterfaceStats(
                index      = idx,
                name       = name.strip('"'),
                status     = _IF_OPER_STATUS.get(status.get(idx, ""), "unknown"),
                in_octets  = self._safe_int(in_oct.get(idx, "0")),
                out_octets = self._safe_int(out_oct.get(idx, "0")),
            ))
        return interfaces

    def is_reachable(self, ip: str) -> bool:
        """
        Quick liveness check — a successful sysDescr GET means the
        device is up and SNMP-reachable. Swallows SNMPError.
        """
        try:
            self.get_sysdescr(ip)
            return True
        except SNMPError:
            return False

    # ── Private helpers ───────────────────────────────────────────────────────

    def _base_cmd(self, binary: str, ip: str) -> list[str]:
        """Build the common snmpget/snmpwalk argument list, target IP last."""
        return [
            binary,
            "-v", "2c",
            "-c", self._community,
            "-t", str(self._timeout),
            "-r", str(self._retries),
            ip,
        ]

    def _run(self, cmd: list[str], ip: str, oid: str) -> str:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._timeout * (self._retries + 1) + 2,
            )
        except subprocess.TimeoutExpired as exc:
            raise SNMPError(ip, oid, "request timed out") from exc

        if result.returncode != 0 or not result.stdout.strip():
            reason = result.stderr.strip() or "no response"
            raise SNMPError(ip, oid, reason)

        return result.stdout

    def _parse_single_value(self, output: str) -> str:
        line = output.strip().splitlines()[0] if output.strip() else ""
        match = _VALUE_LINE_RE.match(line)
        if match:
            return match.group(1).strip().strip('"')
        # Fallback: some responses have no type tag (e.g. INTEGER without label)
        if "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
        return line.strip()

    def _parse_walk(self, output: str) -> dict[str, str]:
        results: dict[str, str] = {}
        for line in output.strip().splitlines():
            match = _WALK_INDEX_RE.match(line)
            if match:
                idx, value = match.groups()
                results[idx] = value.strip().strip('"')
        return results

    def _require_binary(self, name: str) -> None:
        if shutil.which(name) is None:
            raise SNMPError(
                "n/a", "n/a",
                f"'{name}' not found on PATH — install net-snmp-utils / snmp package"
            )

    @staticmethod
    def _safe_int(value: str) -> int:
        digits = re.findall(r"\d+", value)
        return int(digits[0]) if digits else 0