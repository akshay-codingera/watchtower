"""
pipeline/forge/cef.py
=======================
WATCHTOWER — Common Event Format (CEF) Parser

CEF is used by Palo Alto, ArcSight, and a wide range of enterprise
security appliances (see beacon/cartographer.py, which maps
LogFormat.CEF to DeviceType.PALO_ALTO as its strongest signal). Wire
layout, usually arriving inside a standard RFC 3164/5424 envelope:

    CEF:Version|Device Vendor|Device Product|Device Version|
        Signature ID|Name|Severity|[Extension]

Extension is a sequence of "key=value" pairs. Per the CEF spec, values
only need to escape '\\', '=', and '|' — unescaped spaces inside a
value are legal, so a value is read up through the next recognized
"word=" boundary rather than up to the next space.
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

_CEF_RE = re.compile(
    r"CEF:(?P<version>\d+)\|"
    r"(?P<vendor>(?:[^\\|]|\\.)*)\|"
    r"(?P<product>(?:[^\\|]|\\.)*)\|"
    r"(?P<devversion>(?:[^\\|]|\\.)*)\|"
    r"(?P<sigid>(?:[^\\|]|\\.)*)\|"
    r"(?P<name>(?:[^\\|]|\\.)*)\|"
    r"(?P<severity>(?:[^\\|]|\\.)*)\|?"
    r"(?P<extension>.*)$",
    re.DOTALL,
)

# key=value where value runs until the next " key=" or end of string.
_EXTENSION_KV_RE = re.compile(r"(\w+)=((?:\\.|[^\\])*?)(?=(?:\s\w+=)|$)")

_EXTENSION_MAP = {
    "src": "source_ip", "dst": "dest_ip",
    "spt": "source_port", "dpt": "dest_port",
    "proto": "protocol", "suser": "username",
    "act": "action", "deviceAction": "action",
    "cat": "event_type", "msg": "message",
}


def _cef_severity_to_name(raw: str) -> str:
    """CEF severity is 0-10 numeric (or Low/Medium/High/Very-High text)."""
    text = raw.strip().lower()
    text_map = {"low": 3, "medium": 6, "high": 8, "very-high": 10, "unknown": 6}
    if text in text_map:
        value = text_map[text]
    else:
        try:
            value = int(float(raw))
        except ValueError:
            return "NOTICE"
    if value >= 9:
        return "EMERG" if value == 10 else "ALERT"
    if value >= 7:
        return "CRIT" if value == 8 else "ERROR"
    if value >= 4:
        return "WARNING" if value >= 5 else "NOTICE"
    return "INFO" if value >= 1 else "DEBUG"


class CEFParser(ForgeParser):
    """Parses ArcSight/Palo Alto-style Common Event Format messages."""

    format_name = LogFormat.CEF

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        pri, remainder = split_pri(raw)
        if pri is not None:
            record.facility, record.severity = pri_to_facility_severity(pri)

        match = _CEF_RE.search(remainder)
        if not match:
            raise ParseError(raw, "no CEF: header found")

        record.event_type = match.group("name").strip() or match.group("sigid").strip()
        record.severity = _cef_severity_to_name(match.group("severity").strip())
        record.app_name = match.group("product").strip() or match.group("vendor").strip()

        message_from_ext = None
        for key, value in _EXTENSION_KV_RE.findall(match.group("extension")):
            target = _EXTENSION_MAP.get(key)
            if target is None:
                continue
            value = value.strip().replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\")
            if target in ("source_port", "dest_port"):
                if value.isdigit():
                    setattr(record, target, int(value))
                continue
            if target == "message":
                message_from_ext = value
                continue
            setattr(record, target, value)

        record.message = message_from_ext or record.event_type
        record.format = LogFormat.CEF
        return record


__all__ = ["CEFParser"]
