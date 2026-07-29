"""``/api/logs`` and ``/api/stats`` — read-only access to the ledger.

All persistence access goes through ``ledger.archivist`` and
``ledger.indexer``. This module never opens a SQLite connection.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Final

from flask import Blueprint, request

from ledger import archivist as _archivist  # type: ignore[import-not-found]
from ledger import indexer as _indexer  # type: ignore[import-not-found]
from nucleus.telemetry import metrics as telemetry  # type: ignore[import-not-found]

from portal.middleware import login_required, rate_limit
from portal.responses import fail, ok

_LOG: Final = logging.getLogger(__name__)

bp = Blueprint("api_logfeed", __name__, url_prefix="/api")

_MAX_PAGE_SIZE: Final[int] = 500
_DEFAULT_PAGE_SIZE: Final[int] = 100


def _clamp_int(raw: str | None, default: int, minimum: int, maximum: int) -> int:
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _record_to_dict(record: Any) -> dict[str, Any]:
    if isinstance(record, dict):
        return record
    if hasattr(record, "to_dict"):
        return dict(record.to_dict())
    return {
        "id": getattr(record, "id", None),
        "timestamp": getattr(record, "timestamp", None),
        "source_ip": getattr(record, "source_ip", None),
        "hostname": getattr(record, "hostname", None),
        "severity": getattr(record, "severity", None),
        "facility": getattr(record, "facility", None),
        "message": getattr(record, "message", None),
        "hash": getattr(record, "hash", None),
    }


@bp.get("/logs")
@login_required
@rate_limit(capacity=120, per_seconds=60.0)
def list_logs() -> Any:
    """Return a paginated slice of log records.

    Query parameters:
        q:          FTS query string (optional)
        severity:   comma-separated severity levels
        source_ip:  filter by source IP
        since:      ISO-8601 lower bound (inclusive)
        until:      ISO-8601 upper bound (exclusive)
        limit:      1..500, default 100
        offset:     >= 0, default 0
    """
    limit = _clamp_int(request.args.get("limit"), _DEFAULT_PAGE_SIZE, 1, _MAX_PAGE_SIZE)
    offset = _clamp_int(request.args.get("offset"), 0, 0, 10_000_000)
    since = _parse_iso(request.args.get("since"))
    until = _parse_iso(request.args.get("until"))
    severity_raw = request.args.get("severity", "").strip()
    severity = [s.strip() for s in severity_raw.split(",") if s.strip()] or None
    source_ip = request.args.get("source_ip") or None
    query = (request.args.get("q") or "").strip() or None

    try:
        if query:
            rows = _indexer.fts_query(
                query=query,
                limit=limit,
                offset=offset,
                since=since,
                until=until,
                severity=severity,
                source_ip=source_ip,
            )
            total = _indexer.fts_count(
                query=query, since=since, until=until,
                severity=severity, source_ip=source_ip,
            )
        else:
            rows = _archivist.search_logs(
                limit=limit,
                offset=offset,
                since=since,
                until=until,
                severity=severity,
                source_ip=source_ip,
            )
            total = _archivist.count_logs(
                since=since, until=until,
                severity=severity, source_ip=source_ip,
            )
    except ValueError as exc:
        return fail("validation_error", str(exc), status=400)

    return ok(
        {
            "items": [_record_to_dict(r) for r in rows],
            "limit": limit,
            "offset": offset,
            "total": total,
        }
    )


@bp.get("/logs/<log_id>")
@login_required
def get_log(log_id: str) -> Any:
    """Fetch a single log record by id."""
    if not log_id or len(log_id) > 128:
        return fail("validation_error", "Invalid log id", status=400)
    row = _archivist.get_log_by_id(log_id)
    if row is None:
        return fail("not_found", "Log record not found", status=404)
    return ok(_record_to_dict(row))


@bp.get("/stats")
@login_required
def stats() -> Any:
    """Return live counters plus recent aggregates.

    ``ledger.archivist.aggregate_stats`` computes long-window aggregates,
    while ``nucleus.telemetry`` exposes in-memory counters.
    """
    window_seconds = _clamp_int(request.args.get("window"), 300, 60, 86_400)
    try:
        counters = telemetry.snapshot()
    except Exception:  # pragma: no cover - defensive
        _LOG.exception("telemetry snapshot failed")
        counters = {}
    try:
        aggregates = _archivist.aggregate_stats(window_seconds=window_seconds)
    except Exception:  # pragma: no cover - defensive
        _LOG.exception("aggregate_stats failed")
        aggregates = {}
    return ok({"counters": counters, "aggregates": aggregates, "window": window_seconds})


@bp.get("/logs/export")
@login_required
@rate_limit(capacity=6, per_seconds=60.0)
def export_logs() -> Any:
    """Trigger an export job for the current filter set."""
    fmt = (request.args.get("format") or "csv").lower()
    if fmt not in {"csv", "json", "ndjson"}:
        return fail("validation_error", "Unsupported export format", status=400)
    since = _parse_iso(request.args.get("since"))
    until = _parse_iso(request.args.get("until"))
    handle = _archivist.export_logs(
        fmt=fmt, since=since, until=until,
        severity=(request.args.get("severity") or "").split(",") or None,
        source_ip=request.args.get("source_ip") or None,
    )
    return ok({"job": handle})


__all__ = ["bp"]
