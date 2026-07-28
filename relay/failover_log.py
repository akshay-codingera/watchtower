"""
relay/failover_log.py
=======================
WATCHTOWER — Failover Event Recorder

Thin semantic layer over Scribe.write_failover_event() /
Archivist.fetch_failover_log(), same pattern as chronicle/auditor.py
and chronicle/trail.py. This is the only place in relay/ that touches
the ledger — heartbeat.py, consensus.py, and replicator.py all return
plain data and never write to SQLite themselves.

Wire this into heartbeat.py's on_transition callback so every VRRP
role change gets a permanent record, and into consensus.py so a
promotion decision (and, just as importantly, a *refused* promotion
from the split-brain guard) is auditable after the fact.
"""

from __future__ import annotations

import logging

from ledger.scribe import Scribe
from ledger.archivist import Archivist
from relay.heartbeat import RoleTransition

logger = logging.getLogger(__name__)


class FailoverLog:
    """
    Records and queries HA events.

    Args:
        scribe:    Scribe instance for writes.
        archivist: Archivist instance for reads.
        this_server: This node's own hostname/IP, used as the default
                     from_server/to_server value where relevant.
    """

    def __init__(self, scribe: Scribe, archivist: Archivist, this_server: str = "") -> None:
        self._scribe    = scribe
        self._archivist = archivist
        self._this_server = this_server

    def record_transition(self, transition: RoleTransition, virtual_ip: str = "") -> None:
        """
        Record a heartbeat.py role transition. Wire directly as (or
        from within) Heartbeat's on_transition callback:

            failover_log = FailoverLog(scribe, archivist, this_server="node-a")
            heartbeat = Heartbeat(cfg.relay.virtual_ip,
                                   on_transition=lambda t: failover_log.record_transition(t, cfg.relay.virtual_ip))
        """
        event_type = f"role_change_{transition.old_role}_to_{transition.new_role}"
        self._scribe.write_failover_event(
            event_type=event_type,
            from_server=self._this_server if transition.old_role == "primary" else "",
            to_server=self._this_server if transition.new_role == "primary" else "",
            virtual_ip=virtual_ip,
            detail=f"detected via {transition.detected_via}",
        )

    def record_promotion(self, from_server: str, virtual_ip: str, reason: str, duration_sec: float | None = None) -> None:
        """Record this node promoting itself standby → primary."""
        self._scribe.write_failover_event(
            event_type="promotion",
            from_server=from_server,
            to_server=self._this_server,
            virtual_ip=virtual_ip,
            duration_sec=duration_sec,
            detail=reason,
        )
        logger.critical("PROMOTED to primary (was standby): %s", reason)

    def record_demotion(self, to_server: str, virtual_ip: str, reason: str) -> None:
        """Record this node demoting itself primary → standby (e.g. peer recovered, manual failback)."""
        self._scribe.write_failover_event(
            event_type="demotion",
            from_server=self._this_server,
            to_server=to_server,
            virtual_ip=virtual_ip,
            detail=reason,
        )
        logger.warning("Demoted to standby: %s", reason)

    def record_promotion_refused(self, reason: str) -> None:
        """
        Record that a promotion was considered but refused — most
        commonly by consensus.ConsensusChecker.verify_not_isolated()
        returning False. This is a safety event worth its own row:
        an admin should know "we almost split-brained and didn't"
        just as much as "we failed over".
        """
        self._scribe.write_failover_event(
            event_type="promotion_refused",
            from_server=self._this_server,
            detail=reason,
        )
        logger.warning("Promotion refused: %s", reason)

    def record_replication_event(self, event_type: str, detail: str = "") -> None:
        """
        Record a replication-layer event from replicator.py — e.g.
        'replication_restored', 'replica_stale', 'restore_completed'.
        """
        self._scribe.write_failover_event(event_type=event_type, detail=detail)

    def recent(self, limit: int = 50, event_type: str | None = None) -> list[dict]:
        """Fetch recent HA events, newest first. Feeds portal's health/HA page."""
        return self._archivist.fetch_failover_log(limit=limit, event_type=event_type)