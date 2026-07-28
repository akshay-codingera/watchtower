"""``/api/settings``, ``/api/incidents`` and ``/health`` control-plane APIs."""

from __future__ import annotations

import logging
from typing import Any, Final

from flask import Blueprint, request

from dispatch import incident as _incident  # type: ignore[import-not-found]
from dispatch import rulebook as _rulebook  # type: ignore[import-not-found]
from nucleus.config import config as _config  # type: ignore[import-not-found]
from nucleus.telemetry import telemetry  # type: ignore[import-not-found]

from portal.middleware import login_required, role_required
from portal.responses import fail, ok

_LOG: Final = logging.getLogger(__name__)

bp = Blueprint("api_control", __name__)

_EXPOSABLE_SETTINGS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("intake", "udp_port"),
        ("intake", "tls_port"),
        ("ledger", "retention_days"),
        ("portal", "session_lifetime_seconds"),
        ("relay", "peer_ip"),
        ("relay", "mode"),
    }
)


@bp.get("/health")
def health() -> Any:
    """Liveness/readiness probe. Public; no auth required."""
    snapshot: dict[str, Any] = {}
    try:
        snapshot = telemetry.snapshot()
    except Exception:  # pragma: no cover - defensive
        _LOG.exception("telemetry snapshot failed")
    healthy = snapshot.get("healthy", True) if isinstance(snapshot, dict) else True
    payload = {"status": "ok" if healthy else "degraded", "telemetry": snapshot}
    return ok(payload, status=200 if healthy else 503)


@bp.get("/api/settings")
@login_required
def read_settings() -> Any:
    """Return a whitelisted view of runtime settings from ``nucleus.config``."""
    values: dict[str, dict[str, str]] = {}
    for section, option in _EXPOSABLE_SETTINGS:
        if _config.has_option(section, option):
            values.setdefault(section, {})[option] = _config.get(section, option)
    return ok(values)


@bp.get("/api/incidents")
@login_required
def list_incidents() -> Any:
    state = request.args.get("state") or None
    since = request.args.get("since") or None
    incidents = _incident.list_incidents(state=state, since=since)
    normalised = [i if isinstance(i, dict) else getattr(i, "to_dict", lambda: vars(i))()
                  for i in incidents]
    return ok({"items": normalised})


@bp.get("/api/incidents/<incident_id>")
@login_required
def get_incident(incident_id: str) -> Any:
    inc = _incident.get_incident(incident_id)
    if inc is None:
        return fail("not_found", "Incident not found", status=404)
    payload = inc if isinstance(inc, dict) else getattr(inc, "to_dict", lambda: vars(inc))()
    return ok(payload)


@bp.post("/api/incidents/<incident_id>/ack")
@login_required
@role_required("admin", "operator", "analyst")
def acknowledge(incident_id: str) -> Any:
    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip() or None
    result = _incident.acknowledge_incident(incident_id, note=note)
    if result is None:
        return fail("not_found", "Incident not found", status=404)
    return ok(result if isinstance(result, dict) else getattr(result, "to_dict", lambda: vars(result))())


@bp.post("/api/incidents/<incident_id>/resolve")
@login_required
@role_required("admin", "operator")
def resolve(incident_id: str) -> Any:
    body = request.get_json(silent=True) or {}
    note = (body.get("note") or "").strip() or None
    result = _incident.resolve_incident(incident_id, note=note)
    if result is None:
        return fail("not_found", "Incident not found", status=404)
    return ok(result if isinstance(result, dict) else getattr(result, "to_dict", lambda: vars(result))())


@bp.get("/api/rules")
@login_required
def list_rules() -> Any:
    rules = _rulebook.list_rules()
    return ok({"items": [r if isinstance(r, dict) else getattr(r, "to_dict", lambda: vars(r))()
                         for r in rules]})


@bp.get("/api/rules/<rule_id>")
@login_required
def get_rule(rule_id: str) -> Any:
    rule = _rulebook.get_rule(rule_id)
    if rule is None:
        return fail("not_found", "Rule not found", status=404)
    return ok(rule if isinstance(rule, dict) else getattr(rule, "to_dict", lambda: vars(rule))())


@bp.put("/api/rules/<rule_id>")
@login_required
@role_required("admin")
def save_rule(rule_id: str) -> Any:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return fail("validation_error", "JSON body required", status=400)
    saved = _rulebook.save_rule(rule_id, body)
    return ok(saved if isinstance(saved, dict) else getattr(saved, "to_dict", lambda: vars(saved))())


@bp.delete("/api/rules/<rule_id>")
@login_required
@role_required("admin")
def delete_rule(rule_id: str) -> Any:
    removed = _rulebook.delete_rule(rule_id)
    if not removed:
        return fail("not_found", "Rule not found", status=404)
    return ok({"id": rule_id, "removed": True})


__all__ = ["bp"]
