"""
beacon/sonar.py
================
WATCHTOWER — ICMP Ping Sweep

Pings every known device on a schedule to track raw network
reachability, independent of whether that device is currently sending
logs. This is the `ping_status` axis on the devices table — separate
from `status`, which herald.py drives off log activity.

Why both axes matter: a device can be reachable but quiet (nothing
logged in the last hour but still pingable — probably fine), or
unreachable but recently logged (just went down — that's the
interesting case dispatch/rulebook.py should alert on).

Design principle: sonar never blocks on a single slow host. All pings
in a sweep run concurrently via a thread pool sized to avoid hammering
the network, and a single host's timeout never delays the others.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from nucleus.telemetry import metrics
from ledger.vault import Vault
from ledger.scribe import Scribe
from ledger.archivist import Archivist

logger = logging.getLogger(__name__)

# Linux `ping` output line: "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.842 ms"
_RTT_RE = re.compile(r"time[=<]([\d.]+)\s*ms")

_MAX_CONCURRENT_PINGS = 20


@dataclass
class PingResult:
    ip: str
    reachable: bool
    rtt_ms: float | None = None


class Sonar:
    """
    ICMP reachability prober.

    Args:
        scribe:  Scribe instance for writing ping results.
        archivist: Archivist instance for reading the device list to sweep.
        timeout: Per-host ping timeout in seconds.
        max_workers: Concurrent ping processes in a sweep.
    """

    def __init__(
        self,
        scribe: Scribe,
        archivist: Archivist,
        timeout: int = 2,
        max_workers: int = _MAX_CONCURRENT_PINGS,
    ) -> None:
        self._scribe    = scribe
        self._archivist = archivist
        self._timeout   = timeout
        self._max_workers = max_workers

    def ping_one(self, ip: str) -> PingResult:
        """
        Send a single ICMP echo request to one host.

        Args:
            ip: Target IPv4 address.

        Returns:
            PingResult with reachability and RTT (None if unreachable).
        """
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(self._timeout), ip],
                capture_output=True, text=True,
                timeout=self._timeout + 2,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return PingResult(ip=ip, reachable=False)

        if result.returncode != 0:
            return PingResult(ip=ip, reachable=False)

        match = _RTT_RE.search(result.stdout)
        rtt = float(match.group(1)) if match else None
        return PingResult(ip=ip, reachable=True, rtt_ms=rtt)

    def sweep(self) -> dict:
        """
        Ping every device currently in the registry, concurrently, and
        persist each result via the scribe. Call this on a schedule
        (e.g. every cfg.beacon.ping_interval seconds).

        Returns:
            Summary dict: {total, reachable, unreachable, duration_sec}.

        Note:
            This method does not itself apply cfg.beacon.ping_interval —
            the caller (scheduler/jobs) owns timing. sweep() just does
            one full pass.
        """
        devices = self._archivist.fetch_devices()
        ips     = [d["ip"] for d in devices if d.get("ip")]

        if not ips:
            return {"total": 0, "reachable": 0, "unreachable": 0, "duration_sec": 0.0}

        t_start = time.perf_counter()
        reachable_count   = 0
        unreachable_count = 0

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {pool.submit(self.ping_one, ip): ip for ip in ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.warning("Ping worker failed for %s: %s", ip, exc)
                    continue

                self._record_result(result)
                if result.reachable:
                    reachable_count += 1
                    metrics.beacon_ping_successes.increment()
                else:
                    unreachable_count += 1
                    metrics.beacon_ping_failures.increment()

        duration = time.perf_counter() - t_start
        logger.info(
            "Sonar sweep: %d devices, %d reachable, %d unreachable in %.1fs",
            len(ips), reachable_count, unreachable_count, duration
        )
        return {
            "total":         len(ips),
            "reachable":     reachable_count,
            "unreachable":   unreachable_count,
            "duration_sec":  round(duration, 2),
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _record_result(self, result: PingResult) -> None:
        try:
            self._scribe.update_device_ping(result.ip, result.reachable, result.rtt_ms)
        except Exception as exc:
            logger.warning("Failed to record ping result for %s: %s", result.ip, exc)