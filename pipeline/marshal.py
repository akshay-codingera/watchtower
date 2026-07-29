"""
pipeline/marshal.py
=====================
WATCHTOWER — Normalisation

Ties sieve.py's format detection to the right forge/*.py parser and
hands back a fully-populated (but not yet enriched, validated, or
sealed) LogRecord. This is the "normalize -> LogRecord" step in
docs/architecture.md's data-flow diagram.

Fallback contract: if the parser sieve.py picked raises ParseError
(the message didn't actually match its format after all — sieve's
detection is heuristic, not authoritative), marshal falls back to
forge.plaintext.PlaintextParser, which never raises. A record is only
ever dropped upstream of this point (rate limiting, conduit full) —
never here.
"""

from __future__ import annotations

import logging

from nucleus.constants import FACILITY_TO_CATEGORY, LogCategory, LogFormat
from nucleus.exceptions import ParseError
from nucleus.record import LogRecord
from nucleus.telemetry import metrics

from pipeline.forge import ForgeParser
from pipeline.forge.bsd import BSDParser
from pipeline.forge.cef import CEFParser
from pipeline.forge.ietf import IETFParser
from pipeline.forge.irongate import IronGateParser
from pipeline.forge.leef import LEEFParser
from pipeline.forge.pathfinder import CiscoParser
from pipeline.forge.plaintext import PlaintextParser
from pipeline.forge.winevent import WinEventParser
from pipeline.sieve import Sieve

logger = logging.getLogger(__name__)

# One parser instance per format — every parser is stateless (see
# pipeline/forge/__init__.py), so sharing instances across ingest
# worker threads is safe. Fortinet and pfSense share forge/irongate.py;
# JSON shares forge/plaintext.py, which is JSON-aware (see its
# docstring) as well as being the final fallback.
_PARSERS: dict[str, ForgeParser] = {
    LogFormat.RFC3164:   BSDParser(),
    LogFormat.CISCO:     CiscoParser(),
    LogFormat.RFC5424:   IETFParser(),
    LogFormat.CEF:       CEFParser(),
    LogFormat.LEEF:      LEEFParser(),
    LogFormat.WINEVENT:  WinEventParser(),
    LogFormat.FORTINET:  IronGateParser(),
    LogFormat.PFSENSE:   IronGateParser(),
    LogFormat.JSON:      PlaintextParser(),
    LogFormat.PLAINTEXT: PlaintextParser(),
}

_FALLBACK = PlaintextParser()

_sieve = Sieve()


def normalize(record: LogRecord) -> LogRecord:
    """
    Detect format and parse `record.raw_message` into structured fields.

    Args:
        record: A LogRecord fresh off the conduit — raw_message/
                sender_ip/sender_port/transport/received_at already
                set by intake, everything else still at its default.

    Returns:
        The same LogRecord instance, with format/facility/severity/
        hostname/message/etc. populated. log_category is filled in
        from the facility unless a parser already set something more
        specific (irongate.py sets 'firewall' directly).
    """
    detected = _sieve.detect_format(record)
    if detected == LogFormat.UNKNOWN:
        metrics.pipeline_unknown_format.increment()

    parser = _PARSERS.get(detected, _FALLBACK)
    try:
        parser.parse(record)
        metrics.pipeline_parsed_ok.increment()
    except ParseError as exc:
        logger.debug(
            "Parser for format=%s failed (%s) — falling back to plaintext",
            detected, exc,
        )
        metrics.pipeline_parse_errors.increment()
        record.add_parse_error(str(exc))
        _FALLBACK.parse(record)

    metrics.count_format(record.format)
    _assign_log_category(record)
    return record


def _assign_log_category(record: LogRecord) -> None:
    """
    Fill log_category from the facility unless a parser already picked
    something more specific (irongate.py sets LogCategory.FIREWALL
    directly, regardless of which facility the device happened to tag
    the message with).
    """
    if record.log_category and record.log_category != LogCategory.SYSTEM:
        return
    record.log_category = FACILITY_TO_CATEGORY.get(record.facility, LogCategory.SYSTEM)


__all__ = ["normalize"]
