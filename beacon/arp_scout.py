"""
beacon/arp_scout.py
====================
WATCHTOWER — ARP Table Discovery

Reads the local machine's ARP/neighbor table to build an IP → MAC
mapping without sending any probes of its own. This is the cheapest,
quietest form of discovery WATCHTOWER does — it only reads state the
kernel already has from normal network traffic.

Design principle: arp_scout never triggers traffic to populate the
ARP table (no active ARP requests). It reads whatever is already
cached. Pair it with sonar.py's ping sweep if you need to force
entries to appear for currently-silent devices — a ping populates
the ARP cache as a side effect, then a re-scan picks up the MAC.

Linux only. Tries `ip neighbor show` first (iproute2, modern
standard), falls back to parsing /proc/net/arp if `ip` is unavailable.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from nucleus.exceptions import ARPScanError

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# Neighbor states from `ip neighbor show` that indicate a live entry.
# STALE and DELAY are still usable — they just haven't been
# re-verified recently, the MAC is still believed accurate.
_USABLE_STATES = {"REACHABLE", "STALE", "DELAY", "PERMANENT", "NOARP"}


@dataclass
class ARPEntry:
    """A single IP → MAC mapping read from the kernel's neighbor table."""
    ip: str
    mac: str
    interface: str = ""
    state: str = ""

    def is_valid(self) -> bool:
        return bool(_MAC_RE.match(self.mac)) and self.mac.lower() != "00:00:00:00:00:00"


class ARPScout:
    """
    Reads the kernel ARP/neighbor table for IPv4 entries.

    Usage:
        scout   = ARPScout()
        entries = scout.scan()
        for e in entries:
            print(e.ip, e.mac, e.state)
    """

    def __init__(self, subnet_filter: str = "") -> None:
        """
        Args:
            subnet_filter: Optional CIDR string (e.g. "10.0.0.0/24").
                            If set, scan() only returns entries within
                            this subnet. Empty string = no filtering.
        """
        self._subnet_filter = subnet_filter

    def scan(self) -> list[ARPEntry]:
        """
        Read the current ARP/neighbor table.

        Returns:
            List of ARPEntry, valid entries only (incomplete/failed
            neighbor states are silently skipped).

        Raises:
            ARPScanError: If both the `ip` command and /proc/net/arp
                          are unavailable or unreadable.
        """
        try:
            entries = self._scan_via_ip_command()
        except FileNotFoundError:
            logger.debug("`ip` command not found — falling back to /proc/net/arp")
            entries = self._scan_via_proc()
        except subprocess.SubprocessError as exc:
            raise ARPScanError(f"`ip neighbor show` failed: {exc}") from exc

        valid = [e for e in entries if e.is_valid()]

        if self._subnet_filter:
            valid = [e for e in valid if self._in_subnet(e.ip, self._subnet_filter)]

        logger.info("ARP scan found %d usable entries", len(valid))
        return valid

    def to_ip_mac_map(self) -> dict[str, str]:
        """Convenience: scan() collapsed to a simple {ip: mac} dict."""
        return {e.ip: e.mac for e in self.scan()}

    # ── Private scan strategies ───────────────────────────────────────────────

    def _scan_via_ip_command(self) -> list[ARPEntry]:
        """
        Parse `ip neighbor show` output. Typical line:
            192.168.1.10 dev eth0 lladdr 00:1b:d7:aa:bb:cc REACHABLE
        """
        result = subprocess.run(
            ["ip", "neighbor", "show"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        entries: list[ARPEntry] = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            ip = parts[0]
            try:
                dev_idx = parts.index("dev")
                iface = parts[dev_idx + 1]
            except (ValueError, IndexError):
                iface = ""
            try:
                lladdr_idx = parts.index("lladdr")
                mac = parts[lladdr_idx + 1]
            except (ValueError, IndexError):
                continue  # no MAC — incomplete entry
            state = parts[-1].upper()
            if state not in _USABLE_STATES:
                continue
            entries.append(ARPEntry(ip=ip, mac=mac.lower(), interface=iface, state=state))
        return entries

    def _scan_via_proc(self) -> list[ARPEntry]:
        """
        Parse /proc/net/arp as a fallback when `ip` is unavailable.
        Format (whitespace-separated, header row first):
            IP address  HW type  Flags  HW address  Mask  Device
        """
        proc_path = Path("/proc/net/arp")
        if not proc_path.exists():
            raise ARPScanError("Neither `ip` command nor /proc/net/arp available")

        entries: list[ARPEntry] = []
        try:
            lines = proc_path.read_text(encoding="utf-8").splitlines()[1:]  # skip header
        except OSError as exc:
            raise ARPScanError(f"Cannot read /proc/net/arp: {exc}") from exc

        for line in lines:
            parts = line.split()
            if len(parts) < 6:
                continue
            ip, _hw_type, flags, mac, _mask, iface = parts[:6]
            # Flag 0x2 = ATF_COMPLETE — a resolved entry
            if flags != "0x2":
                continue
            entries.append(ARPEntry(ip=ip, mac=mac.lower(), interface=iface, state="REACHABLE"))
        return entries

    @staticmethod
    def _in_subnet(ip: str, cidr: str) -> bool:
        """Check if an IPv4 address falls within a CIDR range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False