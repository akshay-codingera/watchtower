"""``/api/ingest`` — HTTP ingestion endpoint (API key authenticated).

The portal never parses or persists logs. Payloads are pushed onto
``intake.conduit`` for the pipeline to process, exactly as UDP/TCP
listeners do.
"""

from __future__ import annotations

import logging
from typing import Any, Final, Iterable

from flask import Blueprint, request

from intake import conduit as _conduit  # type: ignore[import-not-found]
from nucleus.exceptions import (  # type: ignore[import-not-found]
    AuthFailure,
    RateLimitExceeded,
)
from sentinel_gate import apikey as _apikey  # type: ignore[import-not-found]

from portal.middleware import rate_limit
from portal.responses import fail, ok

_LOG: Final = logging.getLogger(__name__)

bp = Blueprint("api_ingest", __name__, url_prefix="/api")

_MAX_LINE_BYTES: Final[int] = 64 * 1024
_MAX_BATCH_LINES: Final[int] = 1000


def _extract_key() -> str | None:
    key = request.headers.get("X-API-Key")
    if key:
        return key.strip()
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _iter_lines(payload: bytes) -> Iterable[bytes]:
    for chunk in payload.split(b"\n"):
        chunk = chunk.strip()
        if chunk:
            yield chunk


@bp.post("/ingest")
@rate_limit(capacity=600, per_seconds=60.0)
def ingest() -> Any:
    """Accept one or many raw syslog lines for the pipeline.

    Content negotiation:
        * ``text/plain``: one syslog line per request, newline separated
        * ``application/json``: ``{"lines": ["..."]}`` or a bare JSON array
    """
    key = _extract_key()
    if not key:
        return fail("unauthorized", "API key required", status=401)
    try:
        principal = _apikey.validate_api_key(key)
    except AuthFailure:
        principal = None
    if principal is None:
        return fail("unauthorized", "Invalid API key", status=401)

    source = request.remote_addr or "http"
    accepted = 0
    rejected = 0

    try:
        if request.is_json:
            body = request.get_json(silent=True) or {}
            if isinstance(body, list):
                candidates = body
            elif isinstance(body, dict) and isinstance(body.get("lines"), list):
                candidates = body["lines"]
            else:
                return fail(
                    "validation_error",
                    "Expected JSON array or {\"lines\": [...]}",
                    status=400,
                )
            if len(candidates) > _MAX_BATCH_LINES:
                return fail("payload_too_large", "Too many lines", status=413)
            for line in candidates:
                if not isinstance(line, str):
                    rejected += 1
                    continue
                encoded = line.encode("utf-8", errors="replace")
                if not encoded or len(encoded) > _MAX_LINE_BYTES:
                    rejected += 1
                    continue
                _conduit.enqueue(encoded, source=source)
                accepted += 1
        else:
            raw = request.get_data(cache=False)
            if not raw:
                return fail("validation_error", "Empty request body", status=400)
            for line in _iter_lines(raw):
                if len(line) > _MAX_LINE_BYTES:
                    rejected += 1
                    continue
                _conduit.enqueue(line, source=source)
                accepted += 1
                if accepted >= _MAX_BATCH_LINES:
                    break
    except RateLimitExceeded:
        return fail("rate_limited", "Ingest rate limit exceeded", status=429)

    _LOG.info(
        "ingest api_key=%s accepted=%s rejected=%s source=%s",
        getattr(principal, "id", "unknown"),
        accepted,
        rejected,
        source,
    )
    return ok({"accepted": accepted, "rejected": rejected}, status=202)


__all__ = ["bp"]
