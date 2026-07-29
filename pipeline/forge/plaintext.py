"""
pipeline/forge/plaintext.py
==============================
WATCHTOWER — JSON / Unstructured Fallback Parser

Two jobs in one file, since both end up here for the same reason —
neither has a fixed wire envelope the way RFC3164/CEF/LEEF do:

1. Structured JSON application logs (LogFormat.JSON) — single-line
   JSON objects whose shape varies app to app. Nested objects are
   flattened to dot-paths (e.g. {"http":{"method":"GET"}} becomes
   "http.method") so a candidate key list can match either a
   top-level or a nested field with the same lookup. Whatever isn't
   recognized stays in raw_message — this never tries to be a general
   JSON-to-LogRecord mapper, only pulls out the handful of columns
   WATCHTOWER's schema understands.

2. Genuine plaintext (LogFormat.PLAINTEXT / LogFormat.UNKNOWN), and
   marshal.py's fallback for any other parser's ParseError. This half
   never raises — every raw string, however malformed, becomes a
   LogRecord with at least `message` populated, so nothing pipeline
   touches is ever silently discarded before reaching the ledger.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from nucleus.constants import LogFormat, SEVERITY_ALIASES, SEVERITY_NAMES
from nucleus.exceptions import PRIDecodeError
from nucleus.record import LogRecord

from pipeline.forge import ForgeParser
from pipeline.sieve import pri_to_facility_severity, split_pri

logger = logging.getLogger(__name__)

# First matching key (checked in order) wins for each LogRecord field.
# Entries match against a flattened dot-path (see _flatten below).
_FIELD_CANDIDATES: dict[str, tuple[str, ...]] = {
    "message":    ("message", "msg", "log", "text"),
    "severity":   ("level", "severity", "loglevel", "log_level"),
    "timestamp":  ("timestamp", "time", "@timestamp", "ts"),
    "hostname":   ("host", "hostname", "server"),
    "app_name":   ("app", "application", "service", "logger", "logger_name"),
    "username":   ("user", "username", "user_id", "actor"),
    "source_ip":  ("src_ip", "source_ip", "client_ip", "remote_addr", "ip"),
    "dest_ip":    ("dst_ip", "dest_ip", "destination_ip"),
    "event_type": ("event", "event_type", "action_type"),
    "action":     ("action", "outcome", "result"),
}


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to dot-path keys; lists/scalars stop recursion."""
    flat: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flat.update(_flatten(value, path))
    else:
        flat[prefix] = obj
    return flat


class PlaintextParser(ForgeParser):
    """
    JSON-aware fallback parser. Tries structured JSON first; anything
    that isn't a JSON object falls through to a bare best-effort
    plaintext extraction. Never raises.
    """

    format_name = LogFormat.PLAINTEXT

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        try:
            pri, remainder = split_pri(raw)
        except PRIDecodeError:
            pri, remainder = None, raw
        if pri is not None:
            record.facility, record.severity = pri_to_facility_severity(pri)
        remainder = remainder.strip()

        if self._try_parse_json(remainder, record):
            record.format = LogFormat.JSON
            return record

        record.message = remainder or raw.strip()
        record.format = LogFormat.PLAINTEXT
        return record

    def _try_parse_json(self, text: str, record: LogRecord) -> bool:
        if not (text.startswith("{") and text.endswith("}")):
            return False
        try:
            payload = json.loads(text)
        except (ValueError, TypeError):
            return False
        if not isinstance(payload, dict):
            return False

        flat = _flatten(payload)
        for field, candidates in _FIELD_CANDIDATES.items():
            for key in candidates:
                if key in flat and flat[key] not in (None, ""):
                    self._assign(record, field, flat[key])
                    break

        if not record.message:
            record.message = text
        return True

    @staticmethod
    def _assign(record: LogRecord, field: str, value: Any) -> None:
        if field == "severity":
            name = SEVERITY_ALIASES.get(str(value).strip().upper(), str(value).strip().upper())
            if name in SEVERITY_NAMES:
                record.severity = name
            return
        setattr(record, field, str(value))


__all__ = ["PlaintextParser"]
