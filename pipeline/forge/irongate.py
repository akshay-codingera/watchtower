"""
pipeline/forge/irongate.py
=============================
WATCHTOWER — Perimeter Firewall Parser (Fortinet + pfSense)

Both formats below share this file because both are perimeter-firewall
traffic logs keyed on the same handful of LogRecord fields
(source_ip/dest_ip/source_port/dest_port/protocol/action) — one parser
with two small sub-parsers (one per vendor's on-wire shape) is simpler
to keep in sync than duplicating that field-mapping logic across two
files. Both LogFormat.FORTINET and LogFormat.PFSENSE route here.

Fortinet (FortiOS): space-separated key=value (or key="quoted value")
pairs, e.g.:

    date=2024-01-15 time=14:23:01 devname="FGT1" devid="FG100E..."
    logid="0000000013" type="traffic" subtype="forward" srcip=1.2.3.4
    srcport=51000 dstip=8.8.8.8 dstport=443 proto=6 action="accept" ...

pfSense (filterlog): CSV appended after the standard RFC 3164 envelope,
tagged "filterlog", e.g.:

    ,,,1000000103,igb0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,
    60,10.0.0.5,93.184.216.34,54321,443,...

Fields, in order, per pfSense's filterlog(4): rule#, sub-rule#, anchor,
tracker id, real interface, reason, action, direction, IP version,
then (for the common IPv4 case) tos, ecn, ttl, id, offset, flags,
protocol id, protocol name, length, src, dst, and finally src/dst port
for tcp/udp. Rule/anchor width has drifted across pfSense releases, so
only the trailing action/direction/protocol/src/dst/port fields this
parser actually needs are pulled out by fixed offset — anything that
doesn't line up falls back to whatever was already extracted rather
than raising, since a partial firewall record is still useful.

Caveat: this parser's pfSense field offsets are written to the
documented filterlog(4) layout, not verified against a real pfSense
box — see docs/architecture.md's "What's tested vs. what's assumed"
section for the project's convention on flagging that distinction.
Confirm against real pfSense output before relying on it in production.
"""

from __future__ import annotations

import logging
import re

from nucleus.constants import LogCategory, LogFormat
from nucleus.exceptions import ParseError
from nucleus.record import LogRecord

from pipeline.forge import ForgeParser
from pipeline.sieve import pri_to_facility_severity, split_pri

logger = logging.getLogger(__name__)

_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

_FORTINET_MAP = {
    "srcip": "source_ip", "dstip": "dest_ip",
    "srcport": "source_port", "dstport": "dest_port",
    "proto": "protocol", "user": "username",
    "action": "action", "subtype": "event_type", "msg": "message",
}

_PROTO_NUMBER_TO_NAME = {"6": "tcp", "17": "udp", "1": "icmp"}

# Fixed offsets into the comma-split filterlog line (IPv4 only — see
# module docstring).
_PFSENSE_ACTION_IDX = 6
_PFSENSE_IPVER_IDX = 8
_PFSENSE_PROTO_NAME_IDX = 16
_PFSENSE_SRC_IDX = 18
_PFSENSE_DST_IDX = 19
_PFSENSE_SPORT_IDX = 20
_PFSENSE_DPORT_IDX = 21


class IronGateParser(ForgeParser):
    """Parses Fortinet key=value and pfSense filterlog perimeter-firewall logs."""

    format_name = LogFormat.FORTINET

    def parse(self, record: LogRecord) -> LogRecord:
        raw = record.raw_message or ""
        pri, remainder = split_pri(raw)
        if pri is not None:
            record.facility, record.severity = pri_to_facility_severity(pri)

        if "filterlog" in remainder or re.search(r"\bpf\[\d+\]:", remainder):
            self._parse_pfsense(remainder, record)
            record.format = LogFormat.PFSENSE
        elif "=" in remainder:
            self._parse_fortinet(remainder, record)
            record.format = LogFormat.FORTINET
        else:
            raise ParseError(raw, "no Fortinet key=value or pfSense filterlog pattern found")

        record.log_category = LogCategory.FIREWALL
        if not record.message:
            record.message = remainder.strip()
        return record

    # ── Fortinet ─────────────────────────────────────────────────────────────

    def _parse_fortinet(self, text: str, record: LogRecord) -> None:
        for key, value in _KV_RE.findall(text):
            value = value.strip('"')
            target = _FORTINET_MAP.get(key)
            if target is None:
                continue
            if target in ("source_port", "dest_port"):
                if value.isdigit():
                    setattr(record, target, int(value))
                continue
            if target == "protocol" and value in _PROTO_NUMBER_TO_NAME:
                value = _PROTO_NUMBER_TO_NAME[value]
            setattr(record, target, value)
        record.app_name = record.app_name or "fortigate"

    # ── pfSense filterlog ────────────────────────────────────────────────────

    def _parse_pfsense(self, text: str, record: LogRecord) -> None:
        _, marker, payload = text.partition("filterlog:")
        if not marker:
            _, marker, payload = text.partition("filterlog")
        fields = [f.strip() for f in payload.strip(": ").split(",")]
        if len(fields) <= _PFSENSE_IPVER_IDX:
            raise ParseError(text, "pfSense filterlog line too short")

        record.action = fields[_PFSENSE_ACTION_IDX] or record.action
        ip_version = fields[_PFSENSE_IPVER_IDX]

        # IPv4 and IPv6 filterlog lines diverge after the IP-version
        # field with a different number of header fields before the
        # common protocol-name/length/src/dst/sport/dport tail — only
        # the IPv4 layout (by far the common case) is decoded further.
        if ip_version != "4" or len(fields) <= _PFSENSE_DST_IDX:
            return

        try:
            protocol_name = fields[_PFSENSE_PROTO_NAME_IDX]
            record.protocol = protocol_name
            record.source_ip = fields[_PFSENSE_SRC_IDX]
            record.dest_ip = fields[_PFSENSE_DST_IDX]
            if protocol_name in ("tcp", "udp") and len(fields) > _PFSENSE_DPORT_IDX:
                if fields[_PFSENSE_SPORT_IDX].isdigit():
                    record.source_port = int(fields[_PFSENSE_SPORT_IDX])
                if fields[_PFSENSE_DPORT_IDX].isdigit():
                    record.dest_port = int(fields[_PFSENSE_DPORT_IDX])
        except IndexError:
            # Rule/anchor field width varies across pfSense versions —
            # partial extraction (action/direction already set above)
            # beats raising ParseError over a field-count mismatch.
            logger.debug("pfSense filterlog: could not extract full IPv4 tail")


__all__ = ["IronGateParser"]
