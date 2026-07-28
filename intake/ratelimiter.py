"""
intake/ratelimiter.py
======================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

Per-source-IP rate limiting for the intake layer.

Why this exists: a single misbehaving or compromised device can flood
the UDP listener with thousands of messages per second, starving the
conduit queue and drowning out every other device on the network.
Every message is checked against its source IP's token bucket before
it is allowed onto the conduit.

Algorithm: classic token bucket.
    - Each source IP gets a bucket that holds up to `rate` tokens.
    - Tokens refill continuously at `rate` tokens/second.
    - Each incoming message costs 1 token.
    - No tokens left → RateLimitExceeded, message dropped.

cfg.intake.rate_limit == 0 disables rate limiting entirely (useful for
trusted internal testing).

Memory management: buckets for IPs that have gone quiet are evicted
periodically so this doesn't grow unbounded on a busy network.
"""

from __future__ import annotations

import threading
import time

from nucleus.config import cfg
from nucleus.exceptions import RateLimitExceeded
from nucleus.telemetry import metrics

# How long an idle bucket is kept before being evicted, in seconds.
_BUCKET_IDLE_TTL = 300
# How often eviction runs, in seconds.
_EVICT_INTERVAL = 60


class _TokenBucket:
    """A single source IP's token bucket. Not thread-safe on its own —
    always accessed while the owning RateLimiter holds its lock."""

    __slots__ = ("tokens", "capacity", "refill_rate", "last_refill", "last_seen")

    def __init__(self, capacity: float):
        self.capacity    = capacity
        self.tokens      = capacity
        self.refill_rate = capacity  # tokens/sec == the configured rate
        self.last_refill = time.monotonic()
        self.last_seen   = self.last_refill

    def _refill(self) -> None:
        now     = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed <= 0:
            return
        self.tokens      = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self, cost: float = 1.0) -> bool:
        self._refill()
        self.last_seen = self.last_refill
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


class RateLimiter:
    """
    Thread-safe per-source-IP token bucket rate limiter.

    Usage:
        limiter = RateLimiter()
        limiter.check(sender_ip)   # raises RateLimitExceeded if over limit
    """

    def __init__(self, rate_per_sec: int | None = None):
        self._rate = rate_per_sec if rate_per_sec is not None else (
            cfg.intake.rate_limit if cfg is not None else 1000
        )
        self._enabled = self._rate > 0
        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()
        self._last_evict = time.monotonic()

    def check(self, source_ip: str) -> None:
        """
        Consume one token for `source_ip`.

        Raises:
            RateLimitExceeded: the IP has exhausted its budget for
                this window. Caller (listener) should drop the
                message and increment intake_packets_dropped.
        """
        if not self._enabled:
            return

        with self._lock:
            self._maybe_evict()
            bucket = self._buckets.get(source_ip)
            if bucket is None:
                bucket = _TokenBucket(float(self._rate))
                self._buckets[source_ip] = bucket

            if not bucket.consume(1.0):
                raise RateLimitExceeded(source_ip, self._rate, 1)

    def allow(self, source_ip: str) -> bool:
        """Non-raising variant of check() — returns True/False."""
        try:
            self.check(source_ip)
            return True
        except RateLimitExceeded:
            return False

    def _maybe_evict(self) -> None:
        """Drop buckets for IPs that have been idle past the TTL.
        Must be called with self._lock held."""
        now = time.monotonic()
        if now - self._last_evict < _EVICT_INTERVAL:
            return
        self._last_evict = now
        cutoff = now - _BUCKET_IDLE_TTL
        stale = [ip for ip, b in self._buckets.items() if b.last_seen < cutoff]
        for ip in stale:
            del self._buckets[ip]

    def active_source_count(self) -> int:
        with self._lock:
            return len(self._buckets)