"""
sentinel_gate/lockout.py
========================
WATCHTOWER — Brute Force Lockout Manager

Tracks failed login attempts per IP address and enforces
a temporary lockout after too many failures.

Design:
    - Counters stored in memory (fast, no DB overhead for auth checks)
    - Persisted to SQLite audit_trail for post-incident investigation
    - Per-IP tracking (not per-username — we only have one user)
    - After MAX_FAILURES attempts → lock IP for LOCKOUT_DURATION seconds
    - Successful login resets the counter for that IP
    - Counters expire automatically (sliding window)

Thread safety: all state protected by threading.Lock
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

from nucleus.constants import MAX_FAILED_LOGINS, LOCKOUT_DURATION_SECONDS
from nucleus.exceptions import AccountLockedOut
from nucleus.telemetry import metrics

logger = logging.getLogger(__name__)


@dataclass
class _IPState:
    """Per-IP tracking state."""
    failures:     int   = 0
    locked_until: float = 0.0    # epoch seconds
    first_failure:float = 0.0    # epoch seconds of first failure in window
    last_failure: float = 0.0


class LockoutManager:
    """
    In-memory brute force protection for the login endpoint.

    Args:
        max_failures:     Number of failures before lockout (default 5).
        lockout_seconds:  Duration of lockout in seconds (default 300).
        window_seconds:   Failure counting window in seconds (default 600).
    """

    def __init__(
        self,
        max_failures:    int = MAX_FAILED_LOGINS,
        lockout_seconds: int = LOCKOUT_DURATION_SECONDS,
        window_seconds:  int = 600,
    ) -> None:
        self._max_failures    = max_failures
        self._lockout_seconds = lockout_seconds
        self._window_seconds  = window_seconds
        self._state: dict[str, _IPState] = {}
        self._lock            = threading.Lock()

    def check_allowed(self, ip: str) -> None:
        """
        Check if a login attempt from this IP is allowed.

        Args:
            ip: Client IP address.

        Raises:
            AccountLockedOut: If the IP is currently locked out.
        """
        with self._lock:
            state = self._state.get(ip)
            if state is None:
                return   # no history — allow

            now = time.time()

            # Still locked?
            if state.locked_until > now:
                remaining = int(state.locked_until - now)
                raise AccountLockedOut(remaining_seconds=remaining)

            # Window expired? Reset counter
            if (now - state.first_failure) > self._window_seconds:
                self._state.pop(ip, None)

    def record_failure(self, ip: str) -> None:
        """
        Record a failed login attempt from this IP.
        Triggers lockout if max_failures is reached.

        Args:
            ip: Client IP address.
        """
        now = time.time()
        metrics.portal_failed_logins.increment()

        with self._lock:
            state = self._state.get(ip)

            if state is None:
                state = _IPState(
                    failures=1,
                    first_failure=now,
                    last_failure=now
                )
                self._state[ip] = state
            else:
                # Reset window if too old
                if (now - state.first_failure) > self._window_seconds:
                    state.failures     = 1
                    state.first_failure= now
                    state.locked_until = 0.0
                else:
                    state.failures += 1
                state.last_failure = now

            if state.failures >= self._max_failures:
                state.locked_until = now + self._lockout_seconds
                logger.warning(
                    "IP %s locked out after %d failed attempts (locked for %ds)",
                    ip, state.failures, self._lockout_seconds
                )

    def record_success(self, ip: str) -> None:
        """
        Record a successful login — resets the failure counter for this IP.

        Args:
            ip: Client IP address.
        """
        with self._lock:
            self._state.pop(ip, None)

    def is_locked(self, ip: str) -> bool:
        """
        Check if an IP is currently locked without raising.

        Args:
            ip: Client IP address.

        Returns:
            True if the IP is currently locked out.
        """
        with self._lock:
            state = self._state.get(ip)
            if state is None:
                return False
            return state.locked_until > time.time()

    def remaining_lockout(self, ip: str) -> int:
        """
        Return seconds remaining in lockout for an IP, or 0 if not locked.

        Args:
            ip: Client IP address.

        Returns:
            Seconds remaining, or 0.
        """
        with self._lock:
            state = self._state.get(ip)
            if state is None:
                return 0
            remaining = state.locked_until - time.time()
            return max(0, int(remaining))

    def failure_count(self, ip: str) -> int:
        """
        Return current failure count for an IP.

        Args:
            ip: Client IP address.

        Returns:
            Number of failures in the current window.
        """
        with self._lock:
            state = self._state.get(ip)
            return state.failures if state else 0

    def reset(self, ip: str) -> None:
        """
        Manually reset the lockout for an IP (admin action).

        Args:
            ip: Client IP address to unblock.
        """
        with self._lock:
            self._state.pop(ip, None)
            logger.info("Lockout manually reset for IP %s", ip)

    def stats(self) -> dict:
        """
        Return current lockout statistics for the health page.

        Returns:
            Dict with locked_count, tracked_ips, and list of locked IPs.
        """
        now = time.time()
        with self._lock:
            locked = [
                ip for ip, state in self._state.items()
                if state.locked_until > now
            ]
            return {
                "tracked_ips":  len(self._state),
                "locked_count": len(locked),
                "locked_ips":   locked,
            }

    def cleanup_stale(self) -> int:
        """
        Remove stale entries (window expired and not locked).
        Called periodically by scheduler.

        Returns:
            Number of entries removed.
        """
        now   = time.time()
        count = 0
        with self._lock:
            stale = [
                ip for ip, state in self._state.items()
                if state.locked_until <= now
                and (now - state.first_failure) > self._window_seconds
            ]
            for ip in stale:
                del self._state[ip]
                count += 1
        return count