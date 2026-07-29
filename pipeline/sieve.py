"""
pipeline/sieve.py
===================
WATCHTOWER — Format Detection

The first pipeline stage: decides which forge/*.py parser should
handle a given LogRecord's raw_message. Detection is signature-based
and heuristic, not authoritative — marshal.py falls back to
forge/plaintext.py if the parser sieve picked turns out to be wrong.

Detection order matters: formats with an unmistakable leading marker
(CEF:, LEEF:, a bare JSON object, RFC 5424's version digit right after
PRI) are checked first since they can't be confused with anything
else. Looser signature checks — Fortinet's key=value fields, pfSense's
filterlog tag, Cisco's %FACILITY-SEV-MNEMONIC pattern, a Windows-event
EventID= field — come next. RFC 3164 (the classic BSD envelope) and
plain unstructured text are the fallbacks, since almost anything with
a PRI header at least looks like RFC 3164.

This module also owns PRI-header decoding (split_pri /
pri_to_facility_severity) since every forge parser needs it — sieve.py
already has to do it once to make detection decisions, so the other
parsers reuse the same code rather than re-implementing it.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from nucleus.constants import FACILITY_NAMES, PRI_FACILITY_MULTIPLIER, PRI_MAX, SEVERITY_NAMES, LogFormat
from nucleus.exceptions import PRIDecodeError
from nucleus.record import LogRecord

logger = logging.getLogger(__name__)

# ── PRI header ────────────────────────────────────────────────────────────────

_PRI_RE = re.compile(r"^<(\d{1,3})>")


def split_pri(raw: str) -> tuple[Optional[int], str]:
    """
    Split a leading "<PRI>" header off `raw`, if present.

    Args:
        raw: The full raw message, PRI header and all.

    Returns:
        (pri_value, remainder). pri_value is None when no "<...>"
        header is present at all — some relays and plaintext senders
        never include one, which is not itself an error.

    Raises:
        PRIDecodeError: A "<...>" header is present but its value
            exceeds PRI_MAX (23 * 8 + 7).
    """
    match = _PRI_RE.match(raw)
    if not match:
        return None, raw
    pri = int(match.group(1))
    if pri > PRI_MAX:
        raise PRIDecodeError(raw, f"PRI value {pri} exceeds max {PRI_MAX}")
    return pri, raw[match.end():]


def pri_to_facility_severity(pri: int) -> tuple[str, str]:
    """
    Decode a PRI value into (facility_name, severity_name).

    Falls back to ('user', 'INFO') for an out-of-table code rather
    than raising — by the time this is called, split_pri() has
    already validated pri <= PRI_MAX, so an out-of-range facility/
    severity code here would mean the tables themselves are wrong,
    not that the message is malformed.
    """
    facility_code = pri // PRI_FACILITY_MULTIPLIER
    severity_code = pri % PRI_FACILITY_MULTIPLIER
    facility = FACILITY_NAMES[facility_code] if facility_code < len(FACILITY_NAMES) else "user"
    severity = SEVERITY_NAMES[severity_code] if severity_code < len(SEVERITY_NAMES) else "INFO"
    return facility, severity


# ── Format signatures ─────────────────────────────────────────────────────────

_RFC5424_VERSION_RE = re.compile(r"^<\d{1,3}>1 ")
_BSD_TIMESTAMP_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s")
_CISCO_MNEMONIC_RE = re.compile(r"%[A-Z0-9_]+-\d-[A-Z0-9_]+:")
_CEF_RE = re.compile(r"CEF:\d+\|")
_LEEF_RE = re.compile(r"LEEF:(1\.0|2\.0)\|")
_WINEVENT_RE = re.compile(r"\bEventID=\d+\b")
_FORTINET_HINT_RE = re.compile(r"\bdevname=|\blogid=\"?\d{8,}|\bsubtype=")
_PFSENSE_HINT_RE = re.compile(r"\bfilterlog\b|\bpf\[\d+\]:")


class Sieve:
    """
    Stateless format detector — safe to share a single instance across
    every ingest worker thread (no per-call state is kept).
    """

    def detect_format(self, record: LogRecord) -> str:
        """
        Inspect `record.raw_message` and return the LogFormat this
        message most likely uses. Never raises — a message with a
        malformed PRI header, or no recognizable signature at all,
        resolves to LogFormat.PLAINTEXT / LogFormat.UNKNOWN rather
        than propagating an error out of detection itself.
        """
        raw = record.raw_message or ""
        stripped = raw.strip()
        if not stripped:
            return LogFormat.UNKNOWN

        _, remainder = self._safe_split_pri(stripped)

        if _CEF_RE.search(remainder):
            return LogFormat.CEF
        if _LEEF_RE.search(remainder):
            return LogFormat.LEEF
        if self._looks_like_json(remainder):
            return LogFormat.JSON
        if _RFC5424_VERSION_RE.match(stripped):
            return LogFormat.RFC5424
        if _CISCO_MNEMONIC_RE.search(remainder):
            return LogFormat.CISCO
        if _FORTINET_HINT_RE.search(remainder):
            return LogFormat.FORTINET
        if _PFSENSE_HINT_RE.search(remainder):
            return LogFormat.PFSENSE
        if _WINEVENT_RE.search(remainder):
            return LogFormat.WINEVENT
        if _PRI_RE.match(stripped):
            return LogFormat.RFC3164
        if _BSD_TIMESTAMP_RE.match(remainder):
            return LogFormat.RFC3164
        return LogFormat.PLAINTEXT

    @staticmethod
    def _safe_split_pri(raw: str) -> tuple[Optional[int], str]:
        try:
            return split_pri(raw)
        except PRIDecodeError:
            return None, raw

    @staticmethod
    def _looks_like_json(text: str) -> bool:
        text = text.strip()
        if not (text.startswith("{") and text.endswith("}")):
            return False
        try:
            json.loads(text)
        except (ValueError, TypeError):
            return False
        return True


__all__ = ["Sieve", "split_pri", "pri_to_facility_severity"]