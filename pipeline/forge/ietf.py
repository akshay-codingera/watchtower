"""
pipeline/forge/ietf.py
========================
WATCHTOWER — RFC 5424 (IETF structured syslog) Parser

Handles the modern syslog envelope:

    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        (STRUCTURED-DATA|-) [MSG]

Any header field may be the NILVALUE "-", meaning "not present" —
those are left at whatever LogRecord's dataclass defaults already are
rather than being overwritten with a literal "-". STRUCTURED-DATA
(bracketed SD-ID blocks, or "-") is recognized and stripped off so it
never leaks into `message`, but its individual SD-PARAM key/value
pairs are not expanded into LogRecord fields — nothing in WATCHTOWER's
schema maps to arbitrary structured-data element names, so they stay
in raw_message for anyone who needs them.
"""

from __future__ import annotations

import datetime
import logging
import re

from nucleus.constants import LogFormat
from nucleus.exceptions import ParseError, TimestampDecodeError
from nucleus.record import LogRecord

from pipeline.forge import ForgeParser
from pipeline.sieve import pri_to_facility_severity, split_pri

logger = logging.getLogger(__name__)

_NIL = "-"

# <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP
_HEADER_RE = re.compile(
    r"^(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s"
)
# What follows the header is either "-" (no structured data) or one or
# more "[...]" blocks, optionally followed by " MSG".
_STRUCTURED_DATA_RE = re.compile(r"^(?:-|(?:\[(?:[^\]\\]|\\.)*\])+)\s?", re.DOTALL)


class IETFParser(ForgeParser):
    """Parses RFC 5424 structured syslog envelopes."""

    format_name = LogFormat.RFC5424

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        if not raw.strip():
            raise ParseError(raw, "empty message")

        pri, remainder = split_pri(raw)
        if pri is None:
            raise ParseError(raw, "RFC5424 message missing PRI header")
        record.facility, record.severity = pri_to_facility_severity(pri)
        remainder = remainder.lstrip()

        match = _HEADER_RE.match(remainder)
        if not match:
            raise ParseError(raw, "RFC5424 header fields did not match")

        if match.group("hostname") != _NIL:
            record.hostname = match.group("hostname")
        if match.group("app") != _NIL:
            record.app_name = match.group("app")
        if match.group("procid") != _NIL:
            record.proc_id = match.group("procid")
        if match.group("msgid") != _NIL:
            record.msg_id = match.group("msgid")

        record.timestamp = self._parse_timestamp(match.group("timestamp"), raw)

        rest = remainder[match.end():]
        sd_match = _STRUCTURED_DATA_RE.match(rest)
        msg = rest[sd_match.end():] if sd_match else rest
        # Strip a leading UTF-8 BOM some implementations prepend to MSG.
        record.message = msg.lstrip("\ufeff").strip()
        record.format = LogFormat.RFC5424
        return record

    @staticmethod
    def _parse_timestamp(value: str, raw: str) -> str:
        if value == _NIL:
            return ""
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            dt = datetime.datetime.fromisoformat(text)
        except ValueError as exc:
            raise TimestampDecodeError(raw, f"bad RFC5424 timestamp {value!r}") from exc
        return dt.strftime("%Y-%m-%d %H:%M:%S")


__all__ = ["IETFParser"]
