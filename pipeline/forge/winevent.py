"""
pipeline/forge/winevent.py
=============================
WATCHTOWER — Windows Event Log Parser (NXLog / WEF forwarders)

Windows boxes don't speak syslog natively — they arrive via NXLog (or
Windows Event Forwarding through an NXLog/Snare relay) using its
default flattened key=value template, e.g.:

    EventTime=2024-01-15 14:23:01 Hostname=WIN-SRV01 EventType=INFO
    SeverityValue=2 Severity=INFO EventID=4624 SourceName=Microsoft-
    Windows-Security-Auditing Channel=Security AccountName=jsmith
    Message=An account was successfully logged on. ...

"Message" is always the last field and — unlike every other field
here — may itself contain text that looks like "key=value", so it is
captured greedily to the end of the line rather than up to the next
recognized key.
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

# Keys NXLog's default Windows Event template emits. "Message" is
# deliberately last in the alternation and handled as the greedy tail.
_KNOWN_KEYS = (
    "EventTime", "Hostname", "Keywords", "EventType", "SeverityValue",
    "Severity", "EventID", "SourceName", "ProviderGuid", "Version",
    "Task", "OpcodeValue", "RecordNumber", "ProcessID", "ThreadID",
    "Channel", "Domain", "AccountName", "UserID", "AccountType",
)
_KEY_ALTERNATION = "|".join(_KNOWN_KEYS + ("Message",))
_FIELD_RE = re.compile(
    rf"\b(?P<key>{_KEY_ALTERNATION})=(?P<value>.*?)(?=\s+(?:{_KEY_ALTERNATION})=|$)",
    re.DOTALL,
)

_SEVERITY_MAP = {
    "CRITICAL": "CRIT", "ERROR": "ERROR", "WARNING": "WARNING",
    "INFO": "INFO", "AUDIT_SUCCESS": "INFO", "AUDIT_FAILURE": "WARNING",
    "DEBUG": "DEBUG",
}


class WinEventParser(ForgeParser):
    """Parses NXLog/WEF-forwarded Windows Event Log messages."""

    format_name = LogFormat.WINEVENT

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        pri, remainder = split_pri(raw)
        if pri is not None:
            record.facility, record.severity = pri_to_facility_severity(pri)

        fields = {m.group("key"): m.group("value").strip() for m in _FIELD_RE.finditer(remainder)}
        if "EventID" not in fields:
            raise ParseError(raw, "no EventID= field found")

        record.event_type = fields["EventID"]
        record.app_name = fields.get("SourceName", record.app_name)
        if fields.get("Hostname"):
            record.hostname = fields["Hostname"]
        if fields.get("AccountName"):
            record.username = fields["AccountName"]
        if fields.get("Channel"):
            record.msg_id = fields["Channel"]

        severity_key = (fields.get("Severity") or fields.get("EventType") or "").upper()
        if severity_key in _SEVERITY_MAP:
            record.severity = _SEVERITY_MAP[severity_key]

        if fields.get("EventTime"):
            record.timestamp = self._parse_timestamp(fields["EventTime"], raw)

        record.message = fields.get("Message", "").strip() or raw.strip()
        record.format = LogFormat.WINEVENT
        return record

    @staticmethod
    def _parse_timestamp(value: str, raw: str) -> str:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.datetime.strptime(value[:19], fmt).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
        raise TimestampDecodeError(raw, f"bad EventTime {value!r}")


__all__ = ["WinEventParser"]
