"""
pipeline/sentinel.py
======================
WATCHTOWER — Validation and Integrity Sealing

Last pipeline stage before a LogRecord reaches ledger.scribe.write()
(or beacon.herald.register_from_log() / dispatch.correlator.evaluate(),
which run independently off the same sealed record — see
docs/architecture.md's data-flow diagram: "every arrow out of
pipeline/sentinel.py is independent").

Two jobs, always in this order:
    1. validate() — reject anything structurally broken or carrying an
       injection attempt, before it's ever written to SQLite.
    2. seal() — compute and store the integrity hash (LogRecord.seal()),
       exactly once, as the literal last thing that happens to the
       record before it leaves the pipeline.
"""

from __future__ import annotations

import logging

from nucleus.constants import FACILITY_NAMES, SEVERITY_NAMES, Transport
from nucleus.exceptions import InjectionAttempt, ValidationError
from nucleus.record import LogRecord
from nucleus.telemetry import metrics

logger = logging.getLogger(__name__)

# Crude but effective — these substrings have no legitimate reason to
# appear in a syslog message body and are a standard canary set for
# SQL/command/script injection attempts riding in as log content.
# Checked case-insensitively against a handful of free-text fields.
_INJECTION_KEYWORDS: tuple[str, ...] = (
    "' or '1'='1", "; drop table", "union select", "<script",
    "javascript:", "$(", "`; rm -rf", "../../../etc/passwd",
)

_FIELDS_TO_SCREEN = ("message", "hostname", "app_name", "username")


def validate(record: LogRecord) -> LogRecord:
    """
    Check structural validity and screen for injection attempts.

    Args:
        record: A normalized (marshal'd) and enriched LogRecord.

    Returns:
        The same LogRecord, unchanged, if it passes every check.

    Raises:
        ValidationError: Structural problem (bad facility/severity,
            oversized message).
        InjectionAttempt: A blocked keyword was found in a field
            (subclass of ValidationError).
    """
    if record.facility not in FACILITY_NAMES:
        metrics.pipeline_validation_fails.increment()
        raise ValidationError("facility", f"unknown facility {record.facility!r}")

    if record.severity not in SEVERITY_NAMES:
        metrics.pipeline_validation_fails.increment()
        raise ValidationError("severity", f"unknown severity {record.severity!r}")

    if len(record.raw_message) > Transport.MAX_UDP_SIZE:
        metrics.pipeline_validation_fails.increment()
        raise ValidationError(
            "raw_message", f"message exceeds {Transport.MAX_UDP_SIZE} bytes"
        )

    _screen_for_injection(record)
    return record


def _screen_for_injection(record: LogRecord) -> None:
    for field in _FIELDS_TO_SCREEN:
        value = getattr(record, field, "") or ""
        lowered = value.lower()
        for keyword in _INJECTION_KEYWORDS:
            if keyword in lowered:
                metrics.pipeline_injections_blocked.increment()
                raise InjectionAttempt(field, keyword, record.sender_ip)


def seal(record: LogRecord) -> LogRecord:
    """
    Compute and store the integrity hash. Call this only after
    validate() has passed — it is always the literal last pipeline step.
    """
    return record.seal()


def process(record: LogRecord) -> LogRecord:
    """Convenience wrapper: validate() then seal(), in that order."""
    validate(record)
    return seal(record)


__all__ = ["validate", "seal", "process"]
