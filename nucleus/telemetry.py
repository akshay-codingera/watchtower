"""
nucleus/telemetry.py
====================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

Internal performance metrics and health counters.

Design principle: every module in WATCHTOWER that does measurable work
calls into this module. The portal layer reads from here to populate
the /api/metrics and /health endpoints.

This is NOT an external monitoring tool (Prometheus, Datadog).
It is WATCHTOWER's own self-awareness — it knows how fast it is
receiving, parsing, storing, and alerting.

Thread-safety: all counters use atomic operations via threading.Lock.
Reads never block writes for more than microseconds.
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from typing import Optional


# ── Sliding window rate counter ───────────────────────────────────────────────

class RateCounter:
    """
    Tracks events per second over a configurable sliding window.
    Used for messages/sec, parse errors/sec, etc.
    """

    def __init__(self, window_seconds: int = 60):
        self._window  = window_seconds
        self._buckets: dict[int, int] = {}   # second_timestamp → count
        self._lock    = threading.Lock()

    def increment(self, count: int = 1) -> None:
        bucket = int(time.time())
        with self._lock:
            self._buckets[bucket] = self._buckets.get(bucket, 0) + count
            self._evict()

    def rate(self) -> float:
        """Returns average events per second over the window."""
        now = int(time.time())
        with self._lock:
            self._evict()
            total = sum(
                v for k, v in self._buckets.items()
                if now - k <= self._window
            )
        return total / max(self._window, 1)

    def total_in_window(self) -> int:
        now = int(time.time())
        with self._lock:
            self._evict()
            return sum(
                v for k, v in self._buckets.items()
                if now - k <= self._window
            )

    def _evict(self) -> None:
        """Remove buckets older than the window. Call with lock held."""
        cutoff = int(time.time()) - self._window
        self._buckets = {k: v for k, v in self._buckets.items() if k > cutoff}


# ── Counter (monotonically increasing) ───────────────────────────────────────

class Counter:
    """Thread-safe monotonic counter. Never resets."""

    def __init__(self):
        self._value = 0
        self._lock  = threading.Lock()

    def increment(self, n: int = 1) -> None:
        with self._lock:
            self._value += n

    def value(self) -> int:
        with self._lock:
            return self._value


# ── Gauge (can go up and down) ────────────────────────────────────────────────

class Gauge:
    """Thread-safe gauge for values that fluctuate (queue depth, etc.)."""

    def __init__(self, initial: float = 0):
        self._value = initial
        self._lock  = threading.Lock()

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def increment(self, n: float = 1) -> None:
        with self._lock:
            self._value += n

    def decrement(self, n: float = 1) -> None:
        with self._lock:
            self._value = max(0, self._value - n)

    def value(self) -> float:
        with self._lock:
            return self._value


# ── Latency tracker ───────────────────────────────────────────────────────────

class LatencyTracker:
    """
    Tracks min/max/avg latency over a sliding window.
    Used to measure pipeline processing time per message.
    """

    def __init__(self, window_seconds: int = 60):
        self._samples: list[tuple[int, float]] = []   # (timestamp, ms)
        self._lock    = threading.Lock()
        self._window  = window_seconds

    def record(self, ms: float) -> None:
        now = int(time.time())
        with self._lock:
            self._samples.append((now, ms))
            cutoff = now - self._window
            self._samples = [(t, v) for t, v in self._samples if t > cutoff]

    def stats(self) -> dict:
        with self._lock:
            values = [v for _, v in self._samples]
        if not values:
            return {"min_ms": 0, "max_ms": 0, "avg_ms": 0, "samples": 0}
        return {
            "min_ms":  round(min(values), 3),
            "max_ms":  round(max(values), 3),
            "avg_ms":  round(sum(values) / len(values), 3),
            "samples": len(values),
        }


# ── WatchtowerTelemetry — the singleton metrics registry ──────────────────────

class WatchtowerTelemetry:
    """
    Central metrics registry. One instance, imported everywhere.

    Naming convention:
      intake_*    — receiving layer
      pipeline_*  — parsing/transformation layer
      ledger_*    — storage layer
      beacon_*    — discovery/ping layer
      dispatch_*  — alert layer
      portal_*    — web interface layer
    """

    def __init__(self):
        self._start_time = time.time()

        # ── Intake metrics ────────────────────────────────────────────────
        self.intake_packets_received   = Counter()
        self.intake_bytes_received     = Counter()
        self.intake_packets_dropped    = Counter()   # rate limited or queue full
        self.intake_rate               = RateCounter(60)
        self.intake_queue_depth        = Gauge(0)
        self.intake_udp_errors         = Counter()
        self.intake_tcp_connections    = Gauge(0)

        # ── Pipeline metrics ──────────────────────────────────────────────
        self.pipeline_parsed_ok        = Counter()
        self.pipeline_parse_errors     = Counter()
        self.pipeline_unknown_format   = Counter()
        self.pipeline_validation_fails = Counter()
        self.pipeline_injections_blocked = Counter()
        self.pipeline_latency          = LatencyTracker(60)

        # Format breakdown counters
        self.pipeline_format_counts: dict[str, Counter] = {}

        # ── Ledger metrics ────────────────────────────────────────────────
        self.ledger_writes_ok          = Counter()
        self.ledger_write_errors       = Counter()
        self.ledger_rows_total         = Gauge(0)
        self.ledger_db_size_bytes      = Gauge(0)
        self.ledger_write_latency      = LatencyTracker(60)

        # ── Beacon metrics ────────────────────────────────────────────────
        self.beacon_devices_known      = Gauge(0)
        self.beacon_devices_online     = Gauge(0)
        self.beacon_devices_offline    = Gauge(0)
        self.beacon_ping_successes     = Counter()
        self.beacon_ping_failures      = Counter()
        self.beacon_new_devices        = Counter()

        # ── Dispatch metrics ──────────────────────────────────────────────
        self.dispatch_alerts_fired     = Counter()
        self.dispatch_alerts_acked     = Counter()
        self.dispatch_notify_ok        = Counter()
        self.dispatch_notify_errors    = Counter()

        # ── Relay / HA metrics ──────────────────────────────────────────────
        self.relay_role                = Gauge(0)   # 0=standalone,1=backup,2=primary — see relay.heartbeat.ROLE_GAUGE
        self.relay_failovers_total     = Counter()
        self.relay_split_brain_events  = Counter()
        self.relay_peer_unreachable    = Counter()
        self.relay_replication_lag_sec = Gauge(0)
        self.relay_replication_errors  = Counter()

        # ── Portal metrics ────────────────────────────────────────────────
        self.portal_requests_total     = Counter()
        self.portal_sse_subscribers    = Gauge(0)
        self.portal_active_sessions    = Gauge(0)
        self.portal_failed_logins      = Counter()

        self._lock = threading.Lock()

    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    def uptime_human(self) -> str:
        secs = int(self.uptime_seconds())
        days, rem  = divmod(secs, 86400)
        hours, rem = divmod(rem, 3600)
        mins, secs = divmod(rem, 60)
        if days:
            return f"{days}d {hours}h {mins}m"
        if hours:
            return f"{hours}h {mins}m {secs}s"
        return f"{mins}m {secs}s"

    def count_format(self, format_name: str) -> None:
        """Track how many messages of each format we have parsed."""
        if format_name not in self.pipeline_format_counts:
            with self._lock:
                if format_name not in self.pipeline_format_counts:
                    self.pipeline_format_counts[format_name] = Counter()
        self.pipeline_format_counts[format_name].increment()

    def snapshot(self) -> dict:
        """
        Return a complete point-in-time snapshot of all metrics.
        Called by /api/metrics and the health.html page.
        """
        return {
            "uptime":    self.uptime_human(),
            "uptime_sec": round(self.uptime_seconds(), 1),
            "intake": {
                "packets_received":  self.intake_packets_received.value(),
                "bytes_received":    self.intake_bytes_received.value(),
                "packets_dropped":   self.intake_packets_dropped.value(),
                "rate_per_sec":      round(self.intake_rate.rate(), 2),
                "queue_depth":       int(self.intake_queue_depth.value()),
                "tcp_connections":   int(self.intake_tcp_connections.value()),
                "udp_errors":        self.intake_udp_errors.value(),
            },
            "pipeline": {
                "parsed_ok":          self.pipeline_parsed_ok.value(),
                "parse_errors":       self.pipeline_parse_errors.value(),
                "unknown_format":     self.pipeline_unknown_format.value(),
                "validation_fails":   self.pipeline_validation_fails.value(),
                "injections_blocked": self.pipeline_injections_blocked.value(),
                "latency":            self.pipeline_latency.stats(),
                "formats":            {
                    k: v.value()
                    for k, v in self.pipeline_format_counts.items()
                },
            },
            "ledger": {
                "writes_ok":       self.ledger_writes_ok.value(),
                "write_errors":    self.ledger_write_errors.value(),
                "rows_total":      int(self.ledger_rows_total.value()),
                "db_size_bytes":   int(self.ledger_db_size_bytes.value()),
                "write_latency":   self.ledger_write_latency.stats(),
            },
            "beacon": {
                "devices_known":   int(self.beacon_devices_known.value()),
                "devices_online":  int(self.beacon_devices_online.value()),
                "devices_offline": int(self.beacon_devices_offline.value()),
                "new_devices":     self.beacon_new_devices.value(),
                "ping_successes":  self.beacon_ping_successes.value(),
                "ping_failures":   self.beacon_ping_failures.value(),
            },
            "dispatch": {
                "alerts_fired":    self.dispatch_alerts_fired.value(),
                "alerts_acked":    self.dispatch_alerts_acked.value(),
                "notify_ok":       self.dispatch_notify_ok.value(),
                "notify_errors":   self.dispatch_notify_errors.value(),
            },
            "relay": {
                "role":                 int(self.relay_role.value()),
                "failovers_total":      self.relay_failovers_total.value(),
                "split_brain_events":   self.relay_split_brain_events.value(),
                "peer_unreachable":     self.relay_peer_unreachable.value(),
                "replication_lag_sec":  round(self.relay_replication_lag_sec.value(), 2),
                "replication_errors":   self.relay_replication_errors.value(),
            },
            "portal": {
                "requests_total":  self.portal_requests_total.value(),
                "sse_subscribers": int(self.portal_sse_subscribers.value()),
                "active_sessions": int(self.portal_active_sessions.value()),
                "failed_logins":   self.portal_failed_logins.value(),
            },
        }


# ── Module-level singleton ────────────────────────────────────────────────────
# Import this object everywhere that needs to record metrics.

metrics = WatchtowerTelemetry()