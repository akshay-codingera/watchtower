"""
dispatch/incident.py
======================
WATCHTOWER — Alert Lifecycle Management

Owns the open -> acknowledged -> resolved lifecycle for alerts, and is
the one place in dispatch/ that decides "a rule just matched, now what
actually happens" — write the alert_history row, then fan the
notification out to whatever channels the rule's action_json names.

Design principle: opening an incident (DB write) and notifying about
it are kept as two steps, not one atomic operation — the DB write
always happens first and is authoritative. If every notifier fails
(SMTP down, Telegram unreachable, nobody subscribed to SSE), the
incident still exists in alert_history and shows up next time someone
opens the dashboard. Notification failure must never cause an alert
to go unrecorded.
"""

from __future__ import annotations

import logging

from ledger.scribe import Scribe
from ledger.archivist import Archivist
from dispatch.correlator import Correlator, MatchEvent
from dispatch.notifier import NotifierRegistry

logger = logging.getLogger(__name__)


class IncidentManager:
    """
    Alert lifecycle manager.

    Args:
        scribe:     Scribe instance for writes.
        archivist:  Archivist instance for reads.
        notifiers:  NotifierRegistry to dispatch notifications through.
    """

    def __init__(self, scribe: Scribe, archivist: Archivist, notifiers: NotifierRegistry) -> None:
        self._scribe    = scribe
        self._archivist = archivist
        self._notifiers = notifiers

    def open_from_match(self, match: MatchEvent) -> int:
        """
        Open a new incident from a correlator MatchEvent: write the
        alert_history row, then dispatch notifications per the rule's
        action_json. This is the primary entry point — called by
        whatever drives the correlator (typically the pipeline, right
        after sentinel.py, or a dedicated dispatch thread consuming
        matches from a queue).

        Args:
            match: A MatchEvent from Correlator.evaluate().

        Returns:
            The new alert_history row ID (-1 if the DB write itself failed
            and was swallowed by scribe — see Scribe.write_alert).
        """
        alert = Correlator.to_alert_record(match)

        alert_id = self._scribe.write_alert(alert)

        logger.info(
            "Incident opened: rule=%s level=%s device=%s (alert_id=%s)",
            match.rule.name, alert.level, alert.device_ip, alert_id
        )

        if match.rule.action.notify:
            results = self._notifiers.dispatch(match.rule.action.notify, alert, match.rule)
            failed = [ch for ch, ok in results.items() if not ok]
            if failed:
                logger.warning(
                    "Incident %s: notification failed on channel(s): %s",
                    alert_id, ", ".join(failed)
                )

        return alert_id

    def acknowledge(self, alert_id: int, actor: str) -> None:
        """
        Move an incident from open -> acknowledged. Does not resolve it —
        acknowledgement means "a human has seen this and is on it",
        resolution means "this is actually handled".

        Args:
            alert_id: alert_history row ID.
            actor:    Username acknowledging the alert.
        """
        self._scribe.acknowledge_alert(alert_id, actor)
        logger.info("Incident %s acknowledged by %s", alert_id, actor)

    def resolve(self, alert_id: int, notes: str = "") -> None:
        """
        Move an incident to resolved — the terminal state. Valid from
        either open or acknowledged; acknowledgement isn't a hard
        prerequisite (an admin can resolve directly if they already
        know what happened).

        Args:
            alert_id: alert_history row ID.
            notes:    Optional resolution notes.
        """
        self._scribe.resolve_alert(alert_id, notes=notes)
        logger.info("Incident %s resolved", alert_id)

    def open_incidents(self, level: str | None = None, limit: int = 100) -> list[dict]:
        """
        Fetch currently-unresolved incidents — the dashboard's main
        "what's actually still wrong" view. Deliberately filters on
        resolved=False rather than acknowledged=False: an acknowledged-
        but-unresolved incident is still open work.

        Args:
            level: Optional filter to a single alert level.
            limit: Maximum records.

        Returns:
            List of alert_history dicts, newest first.
        """
        return self._archivist.fetch_alerts(resolved=False, level=level, limit=limit)

    def unacknowledged_critical(self, limit: int = 50) -> list[dict]:
        """Convenience: unresolved, unacknowledged critical/high incidents — page-one triage list."""
        rows = self._archivist.fetch_alerts(acknowledged=False, resolved=False, limit=limit)
        return [r for r in rows if r.get("level") in ("critical", "high")]