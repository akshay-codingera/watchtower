"""
dispatch/rulebook.py
======================
WATCHTOWER — Alert Rule Definitions

Owns the shape of an alert rule and the CRUD around it. correlator.py
consumes AlertRule objects from here; it never touches alert_rules
SQL directly (that's ledger/scribe.py + ledger/archivist.py, per the
"ledger owns all SQL" rule — rulebook.py is the only file in dispatch/
that talks to them).

── Condition schema (condition_json) ─────────────────────────────────────────
A condition is a count-over-a-window rule evaluated against LogRecord
fields as they stream through the pipeline:

    {
        "field":     "severity",          # LogRecord attribute name
        "op":        "in",                # eq | ne | in | not_in | contains | gte | lte
        "value":     ["CRIT","ALERT","EMERG"],
        "window_sec": 60,                 # sliding window for the count
        "count":     1,                   # matches required within window to fire
        "group_by":  null                 # optional field — counts are tracked
                                            # per distinct value of this field
                                            # (e.g. group_by "username" for
                                            # "5 failed logins from the same user")
    }

Examples:
    Critical severity, any single occurrence:
        {"field": "severity", "op": "in", "value": ["CRIT","ALERT","EMERG"],
         "window_sec": 60, "count": 1}

    5 failed logins from the same username within 5 minutes:
        {"field": "event_type", "op": "eq", "value": "failed_login",
         "window_sec": 300, "count": 5, "group_by": "username"}

    20+ firewall blocks from the same source IP in a minute (scan detection):
        {"field": "action", "op": "eq", "value": "block",
         "window_sec": 60, "count": 20, "group_by": "source_ip"}

── Action schema (action_json) ────────────────────────────────────────────────
    {
        "notify":       ["email", "telegram", "browser"],  # notifier channel names
        "cooldown_sec": 300   # minimum gap between repeat fires for the same
                                # rule+group_key, so one noisy source can't
                                # spam every notifier on every matching message
    }
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from nucleus.exceptions import RuleLoadError
from ledger.scribe import Scribe
from ledger.archivist import Archivist

logger = logging.getLogger(__name__)

_VALID_OPS = {"eq", "ne", "in", "not_in", "contains", "gte", "lte"}


@dataclass
class AlertCondition:
    field: str
    op: str
    value: object
    window_sec: int = 60
    count: int = 1
    group_by: str | None = None

    def validate(self) -> None:
        if self.op not in _VALID_OPS:
            raise RuleLoadError(f"Invalid condition op: {self.op!r} (must be one of {_VALID_OPS})")
        if self.window_sec < 1:
            raise RuleLoadError(f"window_sec must be >= 1, got {self.window_sec}")
        if self.count < 1:
            raise RuleLoadError(f"count must be >= 1, got {self.count}")


@dataclass
class AlertAction:
    notify: list[str] = field(default_factory=list)
    cooldown_sec: int = 300


@dataclass
class AlertRule:
    id:          int
    name:        str
    description: str
    condition:   AlertCondition
    action:      AlertAction
    level:       str
    enabled:     bool
    builtin:     bool
    fire_count:  int = 0
    last_fired:  str = ""

    @classmethod
    def from_row(cls, row: dict) -> "AlertRule":
        """
        Parse a raw alert_rules DB row (with condition_json/action_json
        as JSON strings) into a typed AlertRule.

        Raises:
            RuleLoadError: If the JSON is malformed or fails validation.
        """
        try:
            cond_dict = json.loads(row["condition_json"])
            action_dict = json.loads(row["action_json"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuleLoadError(f"Rule '{row.get('name')}' has malformed JSON: {exc}") from exc

        try:
            condition = AlertCondition(
                field=cond_dict["field"], op=cond_dict["op"], value=cond_dict["value"],
                window_sec=cond_dict.get("window_sec", 60), count=cond_dict.get("count", 1),
                group_by=cond_dict.get("group_by"),
            )
        except KeyError as exc:
            raise RuleLoadError(f"Rule '{row.get('name')}' condition missing key: {exc}") from exc
        condition.validate()

        action = AlertAction(
            notify=action_dict.get("notify", []),
            cooldown_sec=action_dict.get("cooldown_sec", 300),
        )

        return cls(
            id=row["id"], name=row["name"], description=row.get("description", ""),
            condition=condition, action=action, level=row.get("level", "medium"),
            enabled=bool(row.get("enabled", 1)), builtin=bool(row.get("builtin", 0)),
            fire_count=row.get("fire_count", 0), last_fired=row.get("last_fired") or "",
        )


# ── Built-in rule seeds ────────────────────────────────────────────────────────
# Applied once at first startup (RuleBook.seed_builtins()) if no builtin
# rules exist yet. Deliberately conservative defaults — tune thresholds
# for your actual traffic volume once real data is flowing.

_BUILTIN_RULES: list[dict] = [
    {
        "name": "critical-severity",
        "description": "Any EMERG/ALERT/CRIT severity log line.",
        "condition": {"field": "severity", "op": "in",
                      "value": ["EMERG", "ALERT", "CRIT"], "window_sec": 60, "count": 1},
        "action": {"notify": ["browser"], "cooldown_sec": 60},
        "level": "critical",
    },
    {
        "name": "repeated-failed-logins",
        "description": "5+ failed logins from the same username within 5 minutes.",
        "condition": {"field": "event_type", "op": "eq", "value": "failed_login",
                      "window_sec": 300, "count": 5, "group_by": "username"},
        "action": {"notify": ["browser", "email"], "cooldown_sec": 300},
        "level": "high",
    },
    {
        "name": "firewall-scan-detect",
        "description": "20+ firewall blocks from the same source IP within a minute.",
        "condition": {"field": "action", "op": "eq", "value": "block",
                      "window_sec": 60, "count": 20, "group_by": "source_ip"},
        "action": {"notify": ["browser"], "cooldown_sec": 120},
        "level": "high",
    },
]


class RuleBook:
    """
    Loads and manages alert rule definitions.

    Args:
        scribe:    Scribe instance for writes.
        archivist: Archivist instance for reads.
    """

    def __init__(self, scribe: Scribe, archivist: Archivist) -> None:
        self._scribe    = scribe
        self._archivist = archivist

    def load_active(self) -> list[AlertRule]:
        """
        Load every enabled rule, parsed and validated.

        Returns:
            List of AlertRule. A rule with malformed JSON is logged
            and skipped rather than aborting the whole load — one bad
            rule shouldn't take every other rule down with it.
        """
        rows = self._archivist.fetch_alert_rules(enabled_only=True)
        rules: list[AlertRule] = []
        for row in rows:
            try:
                rules.append(AlertRule.from_row(row))
            except RuleLoadError as exc:
                logger.error("Skipping unloadable rule: %s", exc)
        logger.info("Loaded %d active alert rule(s)", len(rules))
        return rules

    def seed_builtins(self) -> int:
        """
        Insert the built-in rule set if no builtin rules exist yet.
        Safe to call on every startup — it's a no-op after the first run.

        Returns:
            Number of rules inserted (0 if builtins already present).
        """
        existing = self._archivist.fetch_alert_rules()
        if any(r.get("builtin") for r in existing):
            return 0

        inserted = 0
        for seed in _BUILTIN_RULES:
            try:
                self._scribe.create_alert_rule(
                    name=seed["name"], description=seed["description"],
                    condition_json=json.dumps(seed["condition"]),
                    action_json=json.dumps(seed["action"]),
                    level=seed["level"], enabled=True, builtin=True,
                )
                inserted += 1
            except Exception as exc:
                logger.warning("Failed to seed builtin rule '%s': %s", seed["name"], exc)

        logger.info("Seeded %d builtin alert rule(s)", inserted)
        return inserted

    def create(
        self, name: str, description: str, condition: AlertCondition,
        action: AlertAction, level: str = "medium", enabled: bool = True,
    ) -> int:
        """
        Create a new custom rule (never builtin — use seed_builtins()
        for those). Validates the condition before writing.

        Returns:
            Row ID of the new rule.
        """
        condition.validate()
        return self._scribe.create_alert_rule(
            name=name, description=description,
            condition_json=json.dumps(condition.__dict__),
            action_json=json.dumps(action.__dict__),
            level=level, enabled=enabled, builtin=False,
        )

    def update(
        self, rule_id: int, description: str | None = None,
        condition: AlertCondition | None = None, action: AlertAction | None = None,
        level: str | None = None,
    ) -> None:
        """Update an existing rule's description/condition/action/level."""
        if condition is not None:
            condition.validate()
        self._scribe.update_alert_rule(
            rule_id,
            description=description,
            condition_json=json.dumps(condition.__dict__) if condition else None,
            action_json=json.dumps(action.__dict__) if action else None,
            level=level,
        )

    def set_enabled(self, rule_id: int, enabled: bool) -> None:
        self._scribe.set_rule_enabled(rule_id, enabled)

    def delete(self, rule_id: int) -> None:
        """Raises WriteError if the rule is builtin — disable it instead."""
        self._scribe.delete_alert_rule(rule_id)