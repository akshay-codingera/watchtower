"""
pipeline/
==========
WATCHTOWER — Parsing, Validation, and Sealing

Everything between intake's conduit queue and the ledger/beacon/
dispatch fan-out lives here (see docs/architecture.md's data-flow
diagram: sieve.py -> forge/*.py -> marshal.py -> sentinel.py). Nothing
in this package touches SQLite, a socket, or the process's threading
model directly — it is pure per-record transformation, safe to call
from any ingest worker thread.

Public interface:
    from pipeline          import process
    from pipeline.sieve    import Sieve
    from pipeline.marshal  import normalize
    from pipeline.enricher import Enricher
    from pipeline.sentinel import validate, seal
    from pipeline.forge    import ForgeParser   # base class for forge/*.py

process() is the single call site core.py's ingest workers use in
place of the module's placeholder — see core.py's module docstring
("REPLACE ME") for the exact swap-in:

    sieve.detect_format -> forge parser -> marshal.normalize
        -> enricher.enrich -> sentinel.validate/seal
"""

from __future__ import annotations

import logging
import time

from nucleus.record import LogRecord
from nucleus.telemetry import metrics

from pipeline import sentinel
from pipeline.enricher import Enricher
from pipeline.marshal import normalize

logger = logging.getLogger(__name__)

# Enricher is stateless (see enricher.py) — one shared instance is safe
# across every ingest worker thread.
_enricher = Enricher()


def process(record: LogRecord) -> LogRecord:
    """
    Run a single LogRecord through the full pipeline.

    Stages, always in this order: normalize (format detection + field
    extraction) -> enrich (geo/threat/rdns) -> validate (structural +
    injection screening) -> seal (integrity hash). Timed as one unit
    for pipeline_latency regardless of which stage raises.

    Args:
        record: A minimal LogRecord fresh off the conduit — only
                raw_message/sender_ip/sender_port/transport/received_at
                are set (see intake/listener.py's LogRecord.from_raw()).

    Returns:
        The same LogRecord instance, fully populated and sealed —
        ready for ledger.scribe.write() / beacon.herald.register_from_log()
        / dispatch.correlator.evaluate(), which run independently off
        this one sealed record (see docs/architecture.md).

    Raises:
        ValidationError / InjectionAttempt (nucleus.exceptions.PipelineError
        subclasses): if sentinel.validate() rejects the record. Callers
        should catch WatchtowerError per-record and drop just that
        message — see core.py's IngestWorker._run for the pattern.
    """
    started = time.monotonic()
    try:
        normalize(record)
        _enricher.enrich(record)
        sentinel.validate(record)
        sentinel.seal(record)
    finally:
        metrics.pipeline_latency.record((time.monotonic() - started) * 1000)
    return record


__all__ = ["process"]
