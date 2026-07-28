"""
dispatch/correlator.py
========================
WATCHTOWER — Temporal Pattern Matching Engine

Evaluates every LogRecord passing through the pipeline against the
currently loaded AlertRules, tracking per-rule (and optionally
per-group) sliding windows of matching timestamps in memory. When a
window's match count crosses a rule's threshold, the correlator hands
off to dispatch/incident.py to open an incident — it never writes to
the database itself.

Design principle: all state here is in-process memory (deques of
timestamps), not persisted. This is intentional — correlation windows
are measured in seconds to minutes, so state lost on a restart is
never more than a few minutes of matching history, and rebuilding
"5 failed logins in the last 5 minutes" from scratch after a restart
is the correct, safe behavior (better to under-fire briefly after a
restart than to load a stale window and false-positive).

Performance: evaluate() is called once per ingested LogRecord, so it
must stay cheap. Per-rule dict lookups + deque append/popleft are O(1)
amortized; the field getattr + op comparison is the only per-record
cost, and rules are short-circuited (skip immediately on field
mismatch before touching window state).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from nucleus.record import LogRecord, AlertRecord
from nucleus.constants import AlertLevel
from dispatch.rulebook import AlertRule, RuleBook

logger = logging.getLogger(__name__)


@dataclass
class MatchEvent:
    """A rule crossing its threshold — handed to incident.py to open."""
    rule: AlertRule
    group_key: str          # the group_by value, or '' if the rule isn't grouped
    match_count: int
    window_sec: int
    triggering_record: LogRecord


class Correlator:
    """
    In-memory sliding-window rule evaluator.

    Args:
        rulebook: RuleBook instance used to (re)load active rules.
    """

    def __init__(self, rulebook: RuleBook) -> None:
        self._rulebook = rulebook
        self._rules: list[AlertRule] = []
        # window_state[rule_id][group_key] = deque of match timestamps (epoch seconds)
        self._window_state: dict[int, dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        # last_fired[rule_id][group_key] = epoch seconds of last fire, for cooldown
        self._last_fired: dict[int, dict[str, float]] = defaultdict(dict)
        self.reload_rules()

    def reload_rules(self) -> None:
        """
        Re-fetch active rules from the RuleBook. Call this after any
        rule create/update/enable/disable so correlator picks up the
        change without a restart. Existing window state for rules that
        are still active is preserved; state for removed/disabled
        rules is dropped.
        """
        self._rules = self._rulebook.load_active()
        active_ids = {r.id for r in self._rules}
        for rule_id in list(self._window_state.keys()):
            if rule_id not in active_ids:
                del self._window_state[rule_id]
                self._last_fired.pop(rule_id, None)
        logger.info("Correlator reloaded — %d active rule(s)", len(self._rules))

    def evaluate(self, record: LogRecord) -> list[MatchEvent]:
        """
        Check a single LogRecord against every active rule.

        Args:
            record: A sealed LogRecord from the pipeline.

        Returns:
            List of MatchEvent — usually empty. Multiple rules can fire
            off the same record.
        """
        now = time.time()
        events: list[MatchEvent] = []

        for rule in self._rules:
            if not self._field_matches(record, rule):
                continue

            group_key = self._group_key(record, rule)
            window = self._window_state[rule.id][group_key]

            window.append(now)
            self._evict_expired(window, now, rule.condition.window_sec)

            if len(window) < rule.condition.count:
                continue

            if self._in_cooldown(rule.id, group_key, now, rule.action.cooldown_sec):
                continue

            self._last_fired[rule.id][group_key] = now
            events.append(MatchEvent(
                rule=rule, group_key=group_key, match_count=len(window),
                window_sec=rule.condition.window_sec, triggering_record=record,
            ))
            logger.info(
                "Rule matched: %s (group=%r, count=%d/%d in %ds)",
                rule.name, group_key or "(ungrouped)", len(window),
                rule.condition.count, rule.condition.window_sec
            )

        return events

    @staticmethod
    def to_alert_record(match: MatchEvent) -> AlertRecord:
        """
        Build an AlertRecord ready for incident.py to persist, from a
        MatchEvent. The single source of truth for the match-to-alert
        conversion — incident.py calls this rather than re-deriving
        the reason string itself, so the two never drift.
        """
        rec = match.triggering_record
        reason = (
            f"{match.rule.description or match.rule.name} — "
            f"{match.match_count} match(es) in {match.window_sec}s"
        )
        if match.group_key:
            reason += f" (group: {match.group_key})"

        return AlertRecord(
            rule_id=match.rule.id,
            rule_name=match.rule.name,
            level=match.rule.level or AlertLevel.MEDIUM,
            reason=reason,
            device_ip=rec.sender_ip,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _field_matches(record: LogRecord, rule: AlertRule) -> bool:
        cond = rule.condition
        actual = getattr(record, cond.field, None)
        if actual is None:
            return False

        if cond.op == "eq":
            return actual == cond.value
        if cond.op == "ne":
            return actual != cond.value
        if cond.op == "in":
            return actual in cond.value
        if cond.op == "not_in":
            return actual not in cond.value
        if cond.op == "contains":
            return isinstance(actual, str) and str(cond.value) in actual
        if cond.op == "gte":
            return actual >= cond.value
        if cond.op == "lte":
            return actual <= cond.value
        return False

    @staticmethod
    def _group_key(record: LogRecord, rule: AlertRule) -> str:
        if not rule.condition.group_by:
            return ""
        return str(getattr(record, rule.condition.group_by, "") or "")

    @staticmethod
    def _evict_expired(window: deque, now: float, window_sec: int) -> None:
        cutoff = now - window_sec
        while window and window[0] < cutoff:
            window.popleft()

    def _in_cooldown(self, rule_id: int, group_key: str, now: float, cooldown_sec: int) -> bool:
        last = self._last_fired.get(rule_id, {}).get(group_key)
        if last is None:
            return False
        return (now - last) < cooldown_sec