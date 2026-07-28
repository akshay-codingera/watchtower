"""
chronicle/auditor.py
=====================
WATCHTOWER — Audit Event Writer

Thin, semantic layer over Scribe.write_audit(). The scribe only knows
how to insert a raw (actor, action, target, detail, ...) row — Auditor
is where the vocabulary of "what actually happened" lives, so every
call site in sentinel_gate/, portal/, and dispatch/ writes audit
entries with consistent action/target/detail conventions instead of
each inventing its own strings.

Design principle: chronicle never touches SQLite directly (that rule
belongs to ledger/ alone — see ledger/__init__.py). Auditor is a pure
pass-through to Scribe with typed, named methods in place of free-text
action strings scattered across the codebase.

Action string vocabulary (kept small and stable — extend deliberately,
not per call site):
    login, login_failed, logout, session_expired,
    config_change, permission_denied,
    alert_ack, alert_rule_change,
    data_export, search_saved,
    device_note_change,
    api_key_issued, api_key_revoked
"""

from __future__ import annotations

import json
import logging

from ledger.scribe import Scribe

logger = logging.getLogger(__name__)


class Auditor:
    """
    Semantic audit event writer.

    Args:
        scribe: Scribe instance for the underlying insert.
    """

    def __init__(self, scribe: Scribe) -> None:
        self._scribe = scribe

    # ── Authentication events ─────────────────────────────────────────────────

    def login_success(self, actor: str, ip_address: str, user_agent: str, session_id: str) -> None:
        self._write(actor, "login", target="sentinel_gate", result="success",
                    ip_address=ip_address, user_agent=user_agent, session_id=session_id)

    def login_failed(self, actor: str, ip_address: str, user_agent: str, reason: str = "") -> None:
        self._write(actor, "login_failed", target="sentinel_gate", result="failure",
                    detail=reason, ip_address=ip_address, user_agent=user_agent)

    def logout(self, actor: str, session_id: str, ip_address: str = "") -> None:
        self._write(actor, "logout", target="sentinel_gate", result="success",
                    ip_address=ip_address, session_id=session_id)

    def session_expired(self, actor: str, session_id: str) -> None:
        self._write(actor, "session_expired", target="sentinel_gate", result="success",
                    session_id=session_id)

    def account_locked(self, actor: str, ip_address: str, remaining_seconds: int) -> None:
        self._write(actor, "account_locked", target="sentinel_gate", result="failure",
                    detail=f"locked for {remaining_seconds}s", ip_address=ip_address)

    # ── Authorization events ──────────────────────────────────────────────────

    def permission_denied(self, actor: str, target: str, required_role: str, actual_role: str) -> None:
        self._write(actor, "permission_denied", target=target, result="failure",
                    detail=f"requires {required_role}, has {actual_role}")

    def api_key_issued(self, actor: str, key_name: str, role: str) -> None:
        self._write(actor, "api_key_issued", target=key_name, result="success",
                    detail=f"role={role}")

    def api_key_revoked(self, actor: str, key_name: str) -> None:
        self._write(actor, "api_key_revoked", target=key_name, result="success")

    # ── Configuration / admin events ──────────────────────────────────────────

    def config_change(self, actor: str, target: str, before: dict | None = None, after: dict | None = None) -> None:
        """
        Record a configuration change with a before/after diff.

        Args:
            actor:  Who made the change.
            target: What was changed (e.g. 'ledger.retention_days').
            before: Optional dict of the prior values.
            after:  Optional dict of the new values.
        """
        detail = ""
        if before is not None or after is not None:
            detail = json.dumps({"before": before or {}, "after": after or {}}, default=str)
        self._write(actor, "config_change", target=target, result="success", detail=detail)

    def alert_rule_change(self, actor: str, rule_name: str, change_type: str) -> None:
        """change_type: 'created' | 'updated' | 'deleted' | 'enabled' | 'disabled'"""
        self._write(actor, "alert_rule_change", target=rule_name, result="success",
                    detail=change_type)

    def device_note_change(self, actor: str, device_ip: str, note: str) -> None:
        self._write(actor, "device_note_change", target=device_ip, result="success", detail=note)

    # ── Operational events ────────────────────────────────────────────────────

    def alert_ack(self, actor: str, alert_id: int) -> None:
        self._write(actor, "alert_ack", target=f"alert:{alert_id}", result="success")

    def data_export(self, actor: str, target: str, row_count: int, export_format: str) -> None:
        self._write(actor, "data_export", target=target, result="success",
                    detail=f"{row_count} rows as {export_format}")

    def search_saved(self, actor: str, search_name: str) -> None:
        self._write(actor, "search_saved", target=search_name, result="success")

    # ── Generic escape hatch ──────────────────────────────────────────────────

    def custom(
        self, actor: str, action: str, target: str, detail: str = "",
        result: str = "success", ip_address: str = "", user_agent: str = "",
        session_id: str = "",
    ) -> None:
        """
        Write an audit entry outside the named vocabulary above.
        Prefer adding a named method to this class over calling this
        repeatedly with the same action string from multiple call sites —
        that's exactly the drift this module exists to prevent.
        """
        self._write(actor, action, target, detail, result, ip_address, user_agent, session_id)

    # ── Private ────────────────────────────────────────────────────────────────

    def _write(
        self, actor: str, action: str, target: str, detail: str = "",
        result: str = "success", ip_address: str = "", user_agent: str = "",
        session_id: str = "",
    ) -> None:
        self._scribe.write_audit(
            actor=actor or "system",
            action=action,
            target=target,
            detail=detail,
            ip_address=ip_address,
            user_agent=user_agent,
            result=result,
            session_id=session_id,
        )