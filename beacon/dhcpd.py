"""
beacon/dhcpd.py
================
WATCHTOWER — Standalone DHCP server wrapper (lab/test networks only).

WATCHTOWER does not implement the DHCP protocol itself. Hand-writing a DHCP
server is exactly the kind of thing that goes wrong in ways that take down
a whole network segment, not just a single device. Instead, this module
generates a config file for `dnsmasq` (a small, widely deployed DHCP+DNS
server) and manages its process lifecycle — the same "shell out to a real
tool" pattern already used by beacon/snmp_probe.py (calls snmpget) and
beacon/arp_scout.py (calls arp).

    ⚠ SAFETY — READ BEFORE SETTING dhcp_mode = standalone
    -------------------------------------------------------
    Running a second DHCP server on a network segment that already has one
    causes IP conflicts and outages for every device on that segment, not
    just the ones you're trying to monitor. Only point this at an
    interface that is physically or logically isolated from any other
    network — a switch with no uplink to a real LAN, or a VLAN with no
    other DHCP server present.

    This module does NOT scan for an existing DHCP server before starting
    one. That check is on you, every time, before you flip dhcp_mode to
    "standalone".

    Linux only — dnsmasq isn't available on Windows. If your test rig is a
    Windows machine, run this specific piece inside WSL2, or on a separate
    Linux box, not directly on Windows.

    Starting dnsmasq bound to a real interface normally requires root
    (it needs to bind UDP/67 and manage interface state) — run WATCHTOWER
    as root, or grant the CAP_NET_BIND_SERVICE/CAP_NET_ADMIN capabilities
    to the dnsmasq binary ahead of time.
"""

from __future__ import annotations

import ipaddress
import logging
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from nucleus.exceptions import DHCPConfigError, DHCPServerError

logger = logging.getLogger("beacon.dhcpd")

_DNSMASQ_BIN = "dnsmasq"


class DHCPServer:
    """
    Wraps a dnsmasq subprocess configured to hand out DHCP leases with
    Option 7 (log server) pointing devices at WATCHTOWER.

    Usage:
        server = DHCPServer(
            interface="eth1",
            range_start="192.168.50.100",
            range_end="192.168.50.200",
            lease_time="12h",
            option7_target="192.168.50.10",   # WATCHTOWER's own IP
        )
        server.start()
        ...
        server.stop()
    """

    def __init__(
        self,
        interface: str,
        range_start: str,
        range_end: str,
        lease_time: str,
        option7_target: str,
        gateway: str = "",
        dns_servers: list[str] | None = None,
    ):
        self.interface = interface
        self.range_start = range_start
        self.range_end = range_end
        self.lease_time = lease_time
        self.option7_target = option7_target
        self.gateway = gateway
        self.dns_servers = dns_servers or []

        self._validate()
        self._process: subprocess.Popen | None = None
        self._config_path: Path | None = None

    # ── Validation ───────────────────────────────────────────────────────

    def _validate(self) -> None:
        if not self.interface:
            raise DHCPConfigError(
                "beacon.dhcp_interface is not set in config.ini"
            )
        if platform.system() != "Linux":
            raise DHCPServerError(
                "Standalone DHCP mode requires dnsmasq, which is Linux-only. "
                "Run this component inside WSL2 or on a Linux box — not "
                "directly on Windows."
            )
        if shutil.which(_DNSMASQ_BIN) is None:
            raise DHCPServerError(
                "dnsmasq is not installed. Install it first: "
                "'sudo apt install dnsmasq' (Debian/Ubuntu), and make sure "
                "the system dnsmasq service is stopped and disabled — this "
                "module runs its own instance rather than using the "
                "system one."
            )
        try:
            start_ip = ipaddress.ip_address(self.range_start)
            end_ip = ipaddress.ip_address(self.range_end)
        except ValueError as exc:
            raise DHCPConfigError(f"Invalid DHCP range: {exc}") from exc
        if int(end_ip) <= int(start_ip):
            raise DHCPConfigError(
                "beacon.dhcp_range_end must be after beacon.dhcp_range_start"
            )
        try:
            ipaddress.ip_address(self.option7_target)
        except ValueError as exc:
            raise DHCPConfigError(
                f"beacon.dhcp_option7 must be a valid IP address, "
                f"got: {self.option7_target!r}"
            ) from exc
        if self.gateway:
            try:
                ipaddress.ip_address(self.gateway)
            except ValueError as exc:
                raise DHCPConfigError(
                    f"beacon.dhcp_gateway must be a valid IP address, "
                    f"got: {self.gateway!r}"
                ) from exc

    # ── Config generation ───────────────────────────────────────────────

    def _render_config(self) -> str:
        lines = [
            f"interface={self.interface}",
            "bind-interfaces",
            "except-interface=lo",
            "dhcp-authoritative",
            f"dhcp-range={self.range_start},{self.range_end},{self.lease_time}",
            # This is the actual point of this whole module: tell every
            # device that takes a lease where to send its syslog.
            f"dhcp-option=7,{self.option7_target}",
            "log-dhcp",
            # Don't also try to be a DNS server unless asked to — keep
            # this module's footprint to "DHCP + option 7" by default.
            "port=0",
        ]
        if self.gateway:
            lines.append(f"dhcp-option=option:router,{self.gateway}")
        if self.dns_servers:
            lines.append(f"dhcp-option=option:dns-server,{','.join(self.dns_servers)}")
        return "\n".join(lines) + "\n"

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._process is not None:
            logger.warning("dhcpd: start() called but a dnsmasq process is already running")
            return

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", prefix="watchtower-dnsmasq-",
            delete=False, encoding="utf-8",
        )
        tmp.write(self._render_config())
        tmp.close()
        self._config_path = Path(tmp.name)

        logger.warning(
            "Starting standalone DHCP server: interface=%s range=%s-%s "
            "option7(log server)=%s -- confirm this interface has no other "
            "DHCP server on it before this runs.",
            self.interface, self.range_start, self.range_end, self.option7_target,
        )

        try:
            self._process = subprocess.Popen(
                [_DNSMASQ_BIN, "--no-daemon", f"--conf-file={self._config_path}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        except OSError as exc:
            raise DHCPServerError(f"Failed to start dnsmasq: {exc}") from exc

        logger.info("dhcpd: dnsmasq started (pid=%d)", self._process.pid)

    def stop(self) -> None:
        if self._process is None:
            return
        logger.info("dhcpd: stopping dnsmasq (pid=%d)", self._process.pid)
        self._process.terminate()
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning("dhcpd: dnsmasq did not exit in time, killing it")
            self._process.kill()
            self._process.wait(timeout=5)
        self._process = None

        if self._config_path is not None and self._config_path.exists():
            self._config_path.unlink()
        self._config_path = None

    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None
