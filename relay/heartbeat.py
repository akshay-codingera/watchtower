"""
relay/heartbeat.py
====================
WATCHTOWER — VRRP Role Monitor

Determines whether this node currently holds the virtual IP (VIP) —
i.e. whether keepalived considers it MASTER or BACKUP — and tracks
state transitions over time.

Design principle: heartbeat.py does not implement VRRP itself. VRRP is
keepalived's job (see deploy/keepalived/). This module answers one
question cheaply and repeatedly: "does this box currently own the
VIP?" — by checking actual network state (`ip addr show`), not by
trusting keepalived's internal state file, which can go stale if
keepalived crashes without cleaning up after itself.

Two ways to feed state into WATCHTOWER, both supported here:
    1. Poll — call Heartbeat.poll() every cfg.relay.heartbeat_interval
       seconds from a scheduler job. Simple, works with any keepalived
       setup, has up to one interval of detection latency.
    2. Push — point keepalived's notify_master / notify_backup /
       notify_fault scripts at a tiny CLI wrapper that calls
       Heartbeat.on_notify(state) directly. Near-instant, no polling
       delay. Prefer this in production; keep poll() running anyway
       as a correctness backstop in case a notify script fails to fire.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class RelayRole:
    PRIMARY = "primary"
    STANDBY = "standby"
    FAULT   = "fault"
    UNKNOWN = "unknown"


# keepalived notify script states → RelayRole
_KEEPALIVED_STATE_MAP = {
    "MASTER": RelayRole.PRIMARY,
    "BACKUP": RelayRole.STANDBY,
    "FAULT":  RelayRole.FAULT,
}


@dataclass
class RoleTransition:
    old_role: str
    new_role: str
    detected_via: str   # 'poll' or 'notify'
    timestamp: float


class Heartbeat:
    """
    Tracks this node's VRRP role and detects transitions.

    Args:
        virtual_ip: The VIP this node participates in VRRP for
                    (cfg.relay.virtual_ip).
        on_transition: Optional callback invoked with a RoleTransition
                       whenever the role changes. Wire this to
                       relay/failover_log.py in core.py's startup —
                       this module stays decoupled from ledger writes.
    """

    def __init__(self, virtual_ip: str, on_transition=None) -> None:
        self._virtual_ip = virtual_ip
        self._on_transition = on_transition
        self._current_role = RelayRole.UNKNOWN

    @property
    def role(self) -> str:
        """The last known role, without re-checking the network."""
        return self._current_role

    def poll(self) -> str:
        """
        Check current VIP ownership and update state.

        Call on a schedule (cfg.relay.heartbeat_interval seconds).

        Returns:
            The current role after this check.
        """
        new_role = RelayRole.PRIMARY if self._has_vip() else RelayRole.STANDBY
        self._transition(new_role, detected_via="poll")
        return self._current_role

    def on_notify(self, keepalived_state: str) -> str:
        """
        Handle a state push from a keepalived notify script.

        Wire this up via a tiny CLI entrypoint, e.g.:
            deploy/keepalived/notify.sh MASTER
                → python -c "from relay.heartbeat import Heartbeat; ..."

        Args:
            keepalived_state: One of 'MASTER', 'BACKUP', 'FAULT' —
                              exactly what keepalived passes to its
                              notify scripts as $2.

        Returns:
            The resulting RelayRole after this notification.
        """
        new_role = _KEEPALIVED_STATE_MAP.get(keepalived_state.upper(), RelayRole.UNKNOWN)
        if new_role == RelayRole.UNKNOWN:
            logger.warning("Unrecognised keepalived state: %r", keepalived_state)
        self._transition(new_role, detected_via="notify")
        return self._current_role

    def is_primary(self) -> bool:
        return self._current_role == RelayRole.PRIMARY

    # ── Private helpers ───────────────────────────────────────────────────────

    def _transition(self, new_role: str, detected_via: str) -> None:
        old_role = self._current_role
        if new_role == old_role:
            return  # no change — nothing to log or notify

        self._current_role = new_role
        logger.info("Relay role transition: %s -> %s (via %s)", old_role, new_role, detected_via)

        if self._on_transition:
            try:
                self._on_transition(RoleTransition(
                    old_role=old_role, new_role=new_role,
                    detected_via=detected_via, timestamp=time.time(),
                ))
            except Exception as exc:
                logger.error("on_transition callback failed: %s", exc)

    def _has_vip(self) -> bool:
        """
        Check whether the VIP is currently assigned to a local interface.

        Uses `ip addr show` rather than parsing keepalived's own state
        file — if keepalived dies uncleanly the VIP can be left
        assigned or removed inconsistently with what its state file
        claims, and the actual interface state is what matters for
        correctness (it's what the network is actually using).
        """
        if not self._virtual_ip:
            return False
        try:
            result = subprocess.run(
                ["ip", "-4", "addr", "show"],
                capture_output=True, text=True, timeout=3, check=True,
            )
        except (subprocess.SubprocessError, FileNotFoundError) as exc:
            logger.warning("Could not check VIP ownership: %s", exc)
            return False
        return self._virtual_ip in result.stdout