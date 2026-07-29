"""
pipeline/forge/pathfinder.py
===============================
WATCHTOWER — Cisco IOS/IOS-XE Mnemonic Parser

Cisco devices wrap the standard RFC 3164 "<PRI>Mmm dd hh:mm:ss HOSTNAME
TAG: MSG" envelope (see forge/bsd.py) around their own
"%FACILITY-SEVERITY-MNEMONIC: description" mnemonic inside MSG, e.g.:

    <189>Jan 15 14:23:01 switch1 234: %LINK-3-UPDOWN: Interface ...

sieve.py flags this as LogFormat.CISCO — distinct from plain RFC3164,
since beacon/cartographer.py's LogFormat -> DeviceType map uses
LogFormat.CISCO as its strongest signal for DeviceType.CISCO_SWITCH,
so the envelope alone isn't enough; the mnemonic has to actually be
there. This parser "finds its way" through the envelope by composing
forge/bsd.py's BSDParser rather than re-implementing timestamp/
hostname/tag parsing, then requires the mnemonic pattern on top — if a
message doesn't have one, it isn't really Cisco after all, and this
parser raises ParseError so marshal.py falls back to plain RFC3164/
plaintext handling instead.
"""

from __future__ import annotations

import logging
import re

from nucleus.constants import LogFormat
from nucleus.exceptions import ParseError
from nucleus.record import LogRecord

from pipeline.forge import ForgeParser
from pipeline.forge.bsd import BSDParser

logger = logging.getLogger(__name__)

_CISCO_MNEMONIC_RE = re.compile(
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<desc>.*)$",
    re.DOTALL,
)

# Cisco's own 0-7 severity scale lines up with syslog's numerically,
# just spelled differently in the mnemonic — map straight across.
_CISCO_SEVERITY_TO_NAME = {
    0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERROR",
    4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}


class CiscoParser(ForgeParser):
    """Parses Cisco IOS/IOS-XE %FACILITY-SEVERITY-MNEMONIC messages."""

    format_name = LogFormat.CISCO

    def __init__(self) -> None:
        # Envelope parsing (PRI/timestamp/hostname/tag) is identical to
        # plain RFC3164 — delegate to it rather than re-implement it.
        self._envelope_parser = BSDParser()

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        self._envelope_parser.parse(record)

        match = _CISCO_MNEMONIC_RE.search(record.message)
        if not match:
            raise ParseError(raw, "no Cisco %FACILITY-SEVERITY-MNEMONIC pattern found")

        record.event_type = match.group("mnemonic")
        record.message = match.group("desc").strip() or record.message
        cisco_severity = int(match.group("severity"))
        # Many IOS images always tag PRI as local7.notice regardless of
        # the mnemonic's actual severity — the mnemonic's own digit is
        # the more trustworthy signal here, so it wins.
        record.severity = _CISCO_SEVERITY_TO_NAME.get(cisco_severity, record.severity)
        record.format = LogFormat.CISCO
        return record


__all__ = ["CiscoParser"]
