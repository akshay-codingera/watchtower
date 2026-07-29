"""
pipeline/forge/leef.py
========================
WATCHTOWER — IBM LEEF Parser (QRadar)

LEEF (Log Event Extended Format) wire layout:

    LEEF:1.0|Vendor|Product|Version|EventID|Attr1=Val1<TAB>Attr2=Val2...
    LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|Attr1=Val1<Delim>...

LEEF 1.0 always uses a tab character between attributes; LEEF 2.0
declares its own delimiter as an extra header field so it can safely
carry values containing tabs. Both are handled here since the only
real difference is which separator splits the attribute block.
"""

from __future__ import annotations

import logging
import re

from nucleus.constants import LogFormat
from nucleus.exceptions import ParseError
from nucleus.record import LogRecord

from pipeline.forge import ForgeParser
from pipeline.sieve import pri_to_facility_severity, split_pri

logger = logging.getLogger(__name__)

_LEEF_HEADER_RE = re.compile(
    r"LEEF:(?P<version>1\.0|2\.0)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<devversion>[^|]*)\|"
    r"(?P<eventid>[^|]*)\|"
    r"(?:(?P<delimiter>[^|]*)\|)?"
    r"(?P<attributes>.*)$",
    re.DOTALL,
)

_ATTRIBUTE_MAP = {
    "src": "source_ip", "dst": "dest_ip",
    "srcPort": "source_port", "dstPort": "dest_port",
    "proto": "protocol", "usrName": "username", "user": "username",
    "cat": "event_type", "msg": "message",
}

_SEVERITY_HINT = {
    "10": "EMERG", "9": "ALERT", "8": "CRIT", "7": "ERROR",
    "6": "WARNING", "5": "WARNING", "4": "NOTICE",
    "3": "INFO", "2": "INFO", "1": "DEBUG",
}


class LEEFParser(ForgeParser):
    """Parses IBM LEEF (Log Event Extended Format) messages, as sent to QRadar."""

    format_name = LogFormat.LEEF

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        pri, remainder = split_pri(raw)
        if pri is not None:
            record.facility, record.severity = pri_to_facility_severity(pri)

        match = _LEEF_HEADER_RE.search(remainder)
        if not match:
            raise ParseError(raw, "no LEEF: header found")

        record.app_name = match.group("product").strip() or match.group("vendor").strip()
        record.event_type = match.group("eventid").strip()

        # LEEF 2.0 declares its own delimiter char; LEEF 1.0 always uses tab.
        delimiter = match.group("delimiter")
        sep = delimiter if delimiter else "\t"

        message_from_attrs = None
        for pair in match.group("attributes").split(sep):
            if "=" not in pair:
                continue
            key, _, value = pair.partition("=")
            key, value = key.strip(), value.strip()
            if key == "sev" and value in _SEVERITY_HINT:
                record.severity = _SEVERITY_HINT[value]
                continue
            target = _ATTRIBUTE_MAP.get(key)
            if target is None:
                continue
            if target in ("source_port", "dest_port"):
                if value.isdigit():
                    setattr(record, target, int(value))
                continue
            if target == "message":
                message_from_attrs = value
                continue
            setattr(record, target, value)

        record.message = message_from_attrs or record.event_type or raw.strip()
        record.format = LogFormat.LEEF
        return record


__all__ = ["LEEFParser"]
