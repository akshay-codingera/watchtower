"""
nucleus/exceptions.py
=====================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

Custom exception hierarchy for the entire platform.

Design principle: every exception carries enough context to be logged
meaningfully without needing to inspect the call stack. Every catch block
in the codebase should be catching a specific WatchtowerError subclass,
never a bare Exception.
"""


# ── Base exception ────────────────────────────────────────────────────────────

class WatchtowerError(Exception):
    """
    Root exception for all WATCHTOWER-specific errors.
    Never raise this directly — always raise a subclass.
    """
    def __init__(self, message: str, context: dict | None = None):
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def __str__(self) -> str:
        if self.context:
            ctx = ", ".join(f"{k}={v}" for k, v in self.context.items())
            return f"{self.message} [{ctx}]"
        return self.message


# ── Configuration exceptions ──────────────────────────────────────────────────

class ConfigError(WatchtowerError):
    """Raised when configuration is missing, malformed, or invalid."""

class ConfigKeyMissing(ConfigError):
    """A required configuration key is absent."""

class ConfigValueInvalid(ConfigError):
    """A configuration value fails validation (wrong type, out of range)."""


# ── Intake / network exceptions ───────────────────────────────────────────────

class IntakeError(WatchtowerError):
    """Base for all intake layer errors."""

class SocketBindError(IntakeError):
    """Failed to bind a UDP or TCP socket to a port."""

class RateLimitExceeded(IntakeError):
    """A source IP has exceeded its allowed message rate."""
    def __init__(self, source_ip: str, limit: int, window_sec: int):
        super().__init__(
            f"Rate limit exceeded for {source_ip}",
            {"source_ip": source_ip, "limit": limit, "window_sec": window_sec}
        )
        self.source_ip  = source_ip
        self.limit      = limit
        self.window_sec = window_sec

class ConduitFullError(IntakeError):
    """The internal processing queue is at capacity — message dropped."""


# ── Pipeline / parsing exceptions ─────────────────────────────────────────────

class PipelineError(WatchtowerError):
    """Base for all pipeline layer errors."""

class ParseError(PipelineError):
    """A log message could not be parsed by any known format."""
    def __init__(self, raw: str, reason: str = ""):
        super().__init__(
            f"Parse failed: {reason}",
            {"raw_preview": raw[:120], "reason": reason}
        )
        self.raw    = raw
        self.reason = reason

class PRIDecodeError(ParseError):
    """The PRI value (<N>) is missing, malformed, or out of range."""

class TimestampDecodeError(ParseError):
    """The timestamp field could not be parsed into a datetime."""

class ValidationError(PipelineError):
    """A log record failed sentinel validation checks."""
    def __init__(self, field: str, reason: str):
        super().__init__(
            f"Validation failed on field '{field}': {reason}",
            {"field": field, "reason": reason}
        )
        self.field  = field
        self.reason = reason

class InjectionAttempt(ValidationError):
    """A blocked keyword was detected in a log field — possible injection."""
    def __init__(self, field: str, keyword: str, source_ip: str):
        super().__init__(field, f"blocked keyword '{keyword}'")
        self.context["source_ip"] = source_ip
        self.context["keyword"]   = keyword
        self.keyword   = keyword
        self.source_ip = source_ip


# ── Ledger / storage exceptions ───────────────────────────────────────────────

class LedgerError(WatchtowerError):
    """Base for all ledger layer errors."""

class DatabaseConnectionError(LedgerError):
    """Could not open or connect to the SQLite database."""

class WriteError(LedgerError):
    """A write operation (INSERT / UPDATE) failed."""

class ReadError(LedgerError):
    """A read operation (SELECT) failed."""

class MigrationError(LedgerError):
    """A database migration script failed to apply."""
    def __init__(self, migration_file: str, reason: str):
        super().__init__(
            f"Migration '{migration_file}' failed: {reason}",
            {"file": migration_file, "reason": reason}
        )

class IntegrityError(LedgerError):
    """A log record's SHA-256 hash does not match — possible tampering."""
    def __init__(self, log_id: int, stored_hash: str, computed_hash: str):
        super().__init__(
            f"Integrity check failed for log_id={log_id}",
            {"log_id": log_id, "stored": stored_hash, "computed": computed_hash}
        )


# ── Beacon / network discovery exceptions ────────────────────────────────────

class BeaconError(WatchtowerError):
    """Base for all beacon layer errors."""

class PingError(BeaconError):
    """ICMP ping to a device failed or timed out."""
    def __init__(self, ip: str, reason: str = "timeout"):
        super().__init__(f"Ping failed for {ip}: {reason}", {"ip": ip})
        self.ip = ip

class SNMPError(BeaconError):
    """SNMP query to a device failed."""
    def __init__(self, ip: str, oid: str, reason: str):
        super().__init__(
            f"SNMP query failed: {reason}",
            {"ip": ip, "oid": oid, "reason": reason}
        )

class ARPScanError(BeaconError):
    """ARP table scan failed."""


# ── Sentinel gate / authentication exceptions ─────────────────────────────────

class AuthError(WatchtowerError):
    """Base for all authentication and authorization errors."""

class InvalidCredentials(AuthError):
    """Login attempt with wrong password."""

class AccountLockedOut(AuthError):
    """Account is temporarily locked due to too many failed attempts."""
    def __init__(self, remaining_seconds: int):
        super().__init__(
            f"Account locked. Try again in {remaining_seconds}s",
            {"remaining_seconds": remaining_seconds}
        )
        self.remaining_seconds = remaining_seconds

class SessionExpired(AuthError):
    """The session token is valid but has expired."""

class SessionInvalid(AuthError):
    """The session token does not exist or has been invalidated."""

class PermissionDenied(AuthError):
    """The authenticated user lacks the required role/permission."""
    def __init__(self, required_role: str, actual_role: str):
        super().__init__(
            f"Permission denied: requires '{required_role}', has '{actual_role}'",
            {"required": required_role, "actual": actual_role}
        )

class APIKeyInvalid(AuthError):
    """The provided API key does not exist or has been revoked."""


# ── Dispatch / alert exceptions ───────────────────────────────────────────────

class DispatchError(WatchtowerError):
    """Base for all dispatch layer errors."""

class RuleLoadError(DispatchError):
    """An alert rule could not be loaded or parsed from its definition."""

class NotificationError(DispatchError):
    """A notification channel failed to deliver an alert."""
    def __init__(self, channel: str, reason: str):
        super().__init__(
            f"Notification via '{channel}' failed: {reason}",
            {"channel": channel, "reason": reason}
        )


# ── Relay / HA exceptions ─────────────────────────────────────────────────────

class RelayError(WatchtowerError):
    """Base for all relay/HA layer errors."""

class ReplicationError(RelayError):
    """Database replication to the standby server failed."""

class SplitBrainError(RelayError):
    """Both servers are simultaneously claiming PRIMARY status."""


# ── Scheduler exceptions ──────────────────────────────────────────────────────

class SchedulerError(WatchtowerError):
    """Base for all scheduler errors."""

class JobExecutionError(SchedulerError):
    """A scheduled job raised an unexpected exception."""
    def __init__(self, job_name: str, reason: str):
        super().__init__(
            f"Scheduled job '{job_name}' failed: {reason}",
            {"job": job_name, "reason": reason}
        )