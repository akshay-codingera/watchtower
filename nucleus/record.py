"""
nucleus/record.py
=================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

Defines LogRecord — the single internal format that every log message
is normalized to, regardless of source format or device type.

Design principle: once a raw message enters the pipeline and exits
marshal.py, it is a LogRecord forever. Every downstream module
(scribe, dispatch, enricher, correlator) works exclusively with
LogRecord objects — never with raw strings or dicts.

This is the contract between all layers.
"""

from __future__ import annotations

import hashlib
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

from nucleus.constants import (
    LogFormat,
    LogCategory,
    DeviceType,
    SEVERITY_NAMES,
    FACILITY_NAMES,
    PRI_DEFAULT,
    INTEGRITY_HASH_FIELDS,
)


@dataclass
class LogRecord:
    """
    The universal internal log record.

    Every field has a default so partial records can be constructed
    during progressive parsing. sentinel.py fills gaps and validates.
    """

    # ── Core syslog fields (RFC 3164 / RFC 5424) ──────────────────────────
    facility:   str = "user"        # facility name string (e.g. 'auth', 'kern')
    severity:   str = "INFO"        # severity name string (e.g. 'ERROR', 'CRIT')
    timestamp:  str = ""            # ISO 8601 string: "2024-01-15 14:23:01"
    hostname:   str = ""            # source hostname or IP from message
    app_name:   str = ""            # application / process name
    proc_id:    str = ""            # process ID (RFC 5424)
    msg_id:     str = ""            # message ID (RFC 5424)
    message:    str = ""            # the actual log message body

    # ── Transport metadata (added by listener.py) ─────────────────────────
    sender_ip:  str = ""            # actual IP that sent the UDP/TCP packet
    sender_port: int = 0            # source port of the sender
    received_at: str = ""          # UTC timestamp when WE received it
    transport:  str = "udp"        # 'udp', 'tcp', 'tls', 'http'

    # ── Format and classification (added by sieve + marshal) ──────────────
    format:       str = LogFormat.UNKNOWN    # which parser handled this
    log_category: str = LogCategory.SYSTEM  # auth/network/firewall/system/app
    device_type:  str = DeviceType.UNKNOWN  # what kind of device sent this

    # ── Extracted fields (populated by forge parsers where available) ──────
    source_ip:   str = ""     # IP extracted from message content (not sender)
    dest_ip:     str = ""     # destination IP (firewall/network logs)
    source_port: int = 0      # source port from message content
    dest_port:   int = 0      # destination port
    protocol:    str = ""     # tcp/udp/icmp extracted from message
    username:    str = ""     # username if present in message
    action:      str = ""     # allow/block/deny/permit (firewall logs)
    event_type:  str = ""     # specific event classification

    # ── Enrichment fields (populated by enricher.py) ──────────────────────
    geo_country:  str = ""    # GeoIP country of sender_ip
    geo_city:     str = ""    # GeoIP city
    geo_isp:      str = ""    # GeoIP ISP / organization
    is_threat:    bool = False # True if sender_ip is on a threat intel list
    threat_score: int = 0     # 0-100 threat reputation score
    rdns:         str = ""    # reverse DNS of sender_ip

    # ── Integrity (populated by sentinel.py) ──────────────────────────────
    integrity_hash: str = ""  # SHA-256 of core fields — tamper detection

    # ── Raw original (always preserved) ───────────────────────────────────
    raw_message: str = ""     # the original bytes decoded to string

    # ── Internal flags ────────────────────────────────────────────────────
    _parse_errors: list[str] = field(default_factory=list, repr=False)

    # ── Class methods ──────────────────────────────────────────────────────

    @classmethod
    def from_raw(cls, raw: str, sender_ip: str,
                 sender_port: int = 0,
                 transport: str = "udp") -> "LogRecord":
        """
        Create a minimal LogRecord from a raw string.
        Used by listener.py before pipeline processing begins.
        """
        now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        return cls(
            raw_message  = raw,
            sender_ip    = sender_ip,
            sender_port  = sender_port,
            transport    = transport,
            received_at  = now,
            hostname     = sender_ip,   # overwritten by parser if message has one
        )

    def compute_integrity_hash(self) -> str:
        """
        Compute SHA-256 hash over the core fields defined in
        INTEGRITY_HASH_FIELDS. Called by sentinel.py before storage.

        The hash proves the record has not been altered after ingestion.
        Store the hash. To verify later: recompute and compare.
        """
        parts = []
        for field_name in INTEGRITY_HASH_FIELDS:
            value = getattr(self, field_name, "")
            parts.append(f"{field_name}={value}")
        payload = "|".join(parts)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def seal(self) -> "LogRecord":
        """
        Compute and store the integrity hash.
        Call this as the final step in sentinel.py before the record
        enters the ledger. After sealing, any modification to the
        core fields will cause integrity verification to fail.
        """
        self.integrity_hash = self.compute_integrity_hash()
        return self

    def verify_integrity(self) -> bool:
        """
        Recompute the hash and compare against the stored one.
        Returns True if the record is intact, False if tampered.
        """
        if not self.integrity_hash:
            return False
        return self.compute_integrity_hash() == self.integrity_hash

    def is_critical(self) -> bool:
        """True if severity is EMERG, ALERT, or CRIT."""
        return self.severity in ("EMERG", "ALERT", "CRIT")

    def is_error_or_above(self) -> bool:
        """True if severity is ERROR or more severe."""
        from nucleus.constants import SEVERITY_CODES
        return SEVERITY_CODES.get(self.severity, 6) <= 3

    def add_parse_error(self, error: str) -> None:
        """Record a non-fatal parse error for diagnostics."""
        self._parse_errors.append(error)

    def has_parse_errors(self) -> bool:
        return len(self._parse_errors) > 0

    def to_dict(self) -> dict:
        """
        Convert to a plain dict for JSON serialization or DB insertion.
        Private fields (starting with _) are excluded.
        """
        d = asdict(self)
        return {k: v for k, v in d.items() if not k.startswith("_")}

    def to_db_row(self) -> dict:
        """
        Convert to a dict matching the database column names.
        Excludes internal-only fields not stored in the DB.
        """
        d = self.to_dict()
        d.pop("_parse_errors", None)
        return d

    def summary(self) -> str:
        """
        One-line human-readable summary. Used in alert notifications
        and log output.
        """
        return (
            f"[{self.severity}] {self.hostname} {self.app_name}: "
            f"{self.message[:120]}"
        )

    def __repr__(self) -> str:
        return (
            f"LogRecord(severity={self.severity!r}, "
            f"hostname={self.hostname!r}, "
            f"app={self.app_name!r}, "
            f"msg={self.message[:60]!r})"
        )


@dataclass
class DeviceRecord:
    """
    Represents a device known to WATCHTOWER.
    Populated by beacon/herald.py on first contact,
    updated by sonar.py on each ping cycle.
    """
    ip:            str  = ""
    hostname:      str  = ""
    friendly_name: str  = ""         # admin-assigned human name
    device_type:   str  = DeviceType.UNKNOWN
    log_category:  str  = LogCategory.SYSTEM
    mac_address:   str  = ""         # from ARP scout
    vendor:        str  = ""         # from MAC OUI lookup
    first_seen:    str  = ""
    last_seen:     str  = ""
    last_log_at:   str  = ""
    msg_count:     int  = 0
    status:        str  = "unknown"  # online/silent/offline/unknown
    ping_status:   str  = "unknown"  # reachable/unreachable/unknown
    ping_rtt_ms:   Optional[float] = None
    last_ping:     str  = ""
    notes:         str  = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def is_online(self) -> bool:
        return self.status == "online"

    def __repr__(self) -> str:
        return (
            f"DeviceRecord(ip={self.ip!r}, "
            f"type={self.device_type!r}, "
            f"status={self.status!r})"
        )


@dataclass
class AlertRecord:
    """
    Represents a fired alert instance.
    Created by dispatch/rulebook.py when a rule condition is met.
    """
    rule_id:        int  = 0
    rule_name:      str  = ""
    level:          str  = "medium"   # critical/high/medium/low/info
    reason:         str  = ""         # human-readable explanation
    fired_at:       str  = ""
    log_id:         int  = 0          # the log entry that triggered it
    device_ip:      str  = ""
    acknowledged:   bool = False
    ack_by:         str  = ""
    ack_at:         str  = ""
    resolved:       bool = False
    resolved_at:    str  = ""
    notes:          str  = ""

    def to_dict(self) -> dict:
        return asdict(self)