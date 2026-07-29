"""
pipeline/forge/bsd.py
=======================
WATCHTOWER — RFC 3164 (BSD syslog) Parser

Handles the classic "<PRI>Mmm dd hh:mm:ss HOSTNAME TAG: MSG" envelope
that the overwhelming majority of switches, routers, APs, and legacy
Unix daemons still send — this is LogFormat.RFC3164.

Cisco IOS/IOS-XE devices use this exact envelope but wrap a
"%FACILITY-SEVERITY-MNEMONIC: description" mnemonic inside MSG.
sieve.py flags that case as the distinct LogFormat.CISCO and routes it
to forge/pathfinder.py instead, which composes this parser for the
envelope and then handles the mnemonic on top of it — see
pathfinder.py's module docstring.
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

# "Jan  5 14:23:01" / "Jan 15 14:23:01" — day is space-padded, not zero-padded.
_TIMESTAMP_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+"
)
_HOSTNAME_RE = re.compile(r"^(?P<host>\S+)\s+")
_TAG_RE = re.compile(r"^(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*")

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class BSDParser(ForgeParser):
    """Parses RFC 3164 envelopes: PRI, traditional timestamp, hostname, tag, message."""

    format_name = LogFormat.RFC3164

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        if not raw.strip():
            raise ParseError(raw, "empty message")

        pri, remainder = split_pri(raw)
        if pri is not None:
            record.facility, record.severity = pri_to_facility_severity(pri)
        remainder = remainder.lstrip()

        remainder = self._parse_timestamp(remainder, record)
        remainder = self._parse_hostname(remainder, record)
        remainder = self._parse_tag(remainder, record)

        record.message = remainder.strip()
        record.format = LogFormat.RFC3164
        return record

    # ── Envelope pieces ────────────────────────────────────────────────────

    def _parse_timestamp(self, text: str, record: LogRecord) -> str:
        match = _TIMESTAMP_RE.match(text)
        if not match:
            # Not fatal — some devices skip the traditional timestamp
            # entirely (e.g. already-ISO upstream). Leave record.timestamp
            # as whatever LogRecord.from_raw() defaulted it to.
            return text
        month = _MONTHS.get(match.group("mon"))
        if month is None:
            raise TimestampDecodeError(text, f"unknown month {match.group('mon')!r}")
        now = datetime.datetime.utcnow()
        try:
            stamp = datetime.datetime(
                now.year, month, int(match.group("day")),
                int(match.group("hh")), int(match.group("mm")), int(match.group("ss")),
            )
        except ValueError as exc:
            raise TimestampDecodeError(text, str(exc)) from exc
        # BSD timestamps carry no year — a "Dec 31" message parsed in
        # early January belongs to last year, not this one.
        if stamp > now + datetime.timedelta(days=1):
            stamp = stamp.replace(year=now.year - 1)
        record.timestamp = stamp.strftime("%Y-%m-%d %H:%M:%S")
        return text[match.end():]

    def _parse_hostname(self, text: str, record: LogRecord) -> str:
        match = _HOSTNAME_RE.match(text)
        if not match:
            return text
        record.hostname = match.group("host")
        return text[match.end():]

    def _parse_tag(self, text: str, record: LogRecord) -> str:
        match = _TAG_RE.match(text)
        if not match:
            return text
        record.app_name = match.group("tag")
        if match.group("pid"):
            record.proc_id = match.group("pid")
        return text[match.end():]


__all__ = ["BSDParser"]
