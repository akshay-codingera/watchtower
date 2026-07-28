"""
intake/intake_metrics.py
=========================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

The per-counter numbers already live in nucleus.telemetry.metrics —
every listener updates those directly, since they're the shared
singleton read by the /health and /api/metrics portal endpoints.

What this module adds on top:
    - snapshot(): an intake-only view of those numbers, shaped for
      quick human/log-line consumption instead of the full nested
      telemetry snapshot.
    - drop_rate(): a convenience ratio, useful for alerting later
      ("if drop_rate > 5% for 5 minutes, something's wrong").
    - a lightweight background thread that logs an intake summary
      line on an interval, so `journalctl -u watchtower -f` gives you
      a heartbeat even before the dashboard exists.
"""

from __future__ import annotations

import logging
import threading

from nucleus.telemetry import metrics

logger = logging.getLogger(__name__)

_DEFAULT_LOG_INTERVAL = 60.0  # seconds


def snapshot() -> dict:
    """Point-in-time view of intake-layer counters only."""
    received = metrics.intake_packets_received.value()
    dropped = metrics.intake_packets_dropped.value()
    return {
        "packets_received": received,
        "bytes_received": metrics.intake_bytes_received.value(),
        "packets_dropped": dropped,
        "rate_per_sec": round(metrics.intake_rate.rate(), 2),
        "queue_depth": int(metrics.intake_queue_depth.value()),
        "tcp_connections": int(metrics.intake_tcp_connections.value()),
        "udp_errors": metrics.intake_udp_errors.value(),
        "drop_rate": drop_rate(),
    }


def drop_rate() -> float:
    """
    Fraction of packets dropped out of everything the listeners have
    seen so far. 0.0 if nothing has been received yet.
    """
    received = metrics.intake_packets_received.value()
    dropped = metrics.intake_packets_dropped.value()
    total = received + dropped
    if total == 0:
        return 0.0
    return round(dropped / total, 4)


class IntakeMetricsLogger:
    """
    Background daemon thread that logs a one-line intake summary on
    a fixed interval. Purely observational — safe to skip entirely
    in tests or minimal setups.

    Usage:
        heartbeat = IntakeMetricsLogger(interval=60)
        heartbeat.start()
        ...
        heartbeat.stop()
    """

    def __init__(self, interval: float = _DEFAULT_LOG_INTERVAL):
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="intake-metrics-logger", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval):
            s = snapshot()
            logger.info(
                "intake: %d pkts/%.1f/s, %d dropped (%.2f%%), queue=%d, tcp_conns=%d",
                s["packets_received"],
                s["rate_per_sec"],
                s["packets_dropped"],
                s["drop_rate"] * 100,
                s["queue_depth"],
                s["tcp_connections"],
            )