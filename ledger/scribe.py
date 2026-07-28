"""
ledger/scribe.py
================
WATCHTOWER — Write Layer

The scribe is responsible exclusively for writing log records to the database.
It never reads. It never builds SQL strings by concatenation.
All SQL uses parameterized queries with named placeholders.

Responsibilities:
    - Single LogRecord insert
    - Batch insert (for high-throughput scenarios)
    - Device record upsert
    - Alert history insert
    - Audit trail insert
    - Intake stats snapshot insert

Performance design:
    For sustained high throughput, use write_batch() which wraps
    many inserts in a single transaction. A single transaction with
    1000 inserts is ~100x faster than 1000 individual commits.
"""

from __future__ import annotations

import logging
import sqlite3
import time
from typing import Sequence

from nucleus.constants import CATEGORY_TABLE, LogCategory
from nucleus.exceptions import WriteError, LedgerError
from nucleus.record import LogRecord, DeviceRecord, AlertRecord
from nucleus.telemetry import metrics
from ledger.vault import Vault

logger = logging.getLogger(__name__)

# ── Column list for log inserts ───────────────────────────────────────────────
# Explicit column list prevents schema changes from silently breaking inserts.
# Must match the columns in 001_initial.sql for every log table.

_LOG_COLUMNS = (
    "timestamp", "received_at", "facility", "severity",
    "hostname", "sender_ip", "sender_port",
    "app_name", "proc_id", "msg_id",
    "message", "raw_message", "format",
    "log_category", "device_type", "transport",
    "source_ip", "dest_ip", "source_port", "dest_port",
    "protocol", "username", "action", "event_type",
    "geo_country", "geo_city", "geo_isp",
    "is_threat", "threat_score", "rdns",
    "integrity_hash",
)

_LOG_PLACEHOLDERS = ", ".join(f":{col}" for col in _LOG_COLUMNS)
_LOG_COLUMN_LIST  = ", ".join(_LOG_COLUMNS)


def _build_insert_sql(table: str) -> str:
    """Build the INSERT SQL for a given log table name."""
    return f"INSERT INTO {table} ({_LOG_COLUMN_LIST}) VALUES ({_LOG_PLACEHOLDERS})"


# Pre-built INSERT statements for each category table
_INSERT_SQL: dict[str, str] = {
    category: _build_insert_sql(table)
    for category, table in CATEGORY_TABLE.items()
}


class Scribe:
    """
    Write-only interface to the WATCHTOWER ledger.

    Args:
        vault: Initialised Vault instance providing database connections.
    """

    def __init__(self, vault: Vault) -> None:
        self._vault = vault

    # ── Log record writes ─────────────────────────────────────────────────────

    def write(self, record: LogRecord) -> int:
        """
        Insert a single LogRecord into the appropriate category table.

        The target table is determined by record.log_category.
        If the category is unrecognised, the record goes to system_logs.

        Args:
            record: Sealed and validated LogRecord from sentinel.py.

        Returns:
            The rowid (id) of the newly inserted row.

        Raises:
            WriteError: If the INSERT fails.
        """
        table    = CATEGORY_TABLE.get(record.log_category, "system_logs")
        sql      = _INSERT_SQL.get(record.log_category)
        if not sql:
            sql = _build_insert_sql(table)

        params = self._record_to_params(record)
        t_start = time.perf_counter()

        try:
            with self._vault.connection() as conn:
                cursor = conn.execute(sql, params)
                row_id = cursor.lastrowid

            elapsed_ms = (time.perf_counter() - t_start) * 1000
            metrics.ledger_writes_ok.increment()
            metrics.ledger_write_latency.record(elapsed_ms)
            return row_id

        except sqlite3.IntegrityError as exc:
            # Duplicate integrity hash — silently discard (deduplication)
            logger.debug("Duplicate record discarded: %s", exc)
            return -1

        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            metrics.ledger_write_errors.increment()
            raise WriteError(
                f"Failed to write LogRecord to {table}: {exc}"
            ) from exc

    def write_batch(self, records: Sequence[LogRecord]) -> int:
        """
        Insert multiple LogRecords in a single transaction.

        Far more efficient than calling write() in a loop.
        All records succeed or all fail — atomicity guaranteed.

        Args:
            records: Sequence of sealed, validated LogRecords.

        Returns:
            Number of records successfully written.

        Raises:
            WriteError: If the batch transaction fails.
        """
        if not records:
            return 0

        # Group records by category for batch execution per table
        groups: dict[str, list[dict]] = {}
        for record in records:
            cat = record.log_category
            if cat not in groups:
                groups[cat] = []
            groups[cat].append(self._record_to_params(record))

        written = 0
        t_start = time.perf_counter()

        try:
            with self._vault.transaction() as conn:
                for category, param_list in groups.items():
                    table = CATEGORY_TABLE.get(category, "system_logs")
                    sql   = _INSERT_SQL.get(category) or _build_insert_sql(table)
                    conn.executemany(sql, param_list)
                    written += len(param_list)

            elapsed_ms = (time.perf_counter() - t_start) * 1000
            metrics.ledger_writes_ok.increment(written)
            metrics.ledger_write_latency.record(elapsed_ms / max(written, 1))
            logger.debug("Batch wrote %d records in %.1fms", written, elapsed_ms)
            return written

        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            metrics.ledger_write_errors.increment(len(records))
            raise WriteError(f"Batch write failed: {exc}") from exc

    # ── Device record upsert ──────────────────────────────────────────────────

    def upsert_device(self, device: DeviceRecord) -> None:
        """
        Insert a new device or update its last_seen and msg_count if it exists.

        Uses INSERT OR IGNORE + UPDATE pattern for race-safe upsert.
        Called by beacon/herald.py on every received log.

        Args:
            device: DeviceRecord with at minimum ip and device_type set.

        Raises:
            WriteError: If the upsert fails.
        """
        try:
            with self._vault.connection() as conn:
                # Insert if new — ignore if IP already exists
                conn.execute("""
                    INSERT OR IGNORE INTO devices
                        (ip, hostname, friendly_name, device_type,
                         mac_address, vendor, first_seen, last_seen,
                         status, notes)
                    VALUES
                        (:ip, :hostname, :friendly_name, :device_type,
                         :mac_address, :vendor, :first_seen, :last_seen,
                         :status, :notes)
                """, {
                    "ip":           device.ip,
                    "hostname":     device.hostname,
                    "friendly_name": device.friendly_name,
                    "device_type":  device.device_type,
                    "mac_address":  device.mac_address,
                    "vendor":       device.vendor,
                    "first_seen":   device.first_seen,
                    "last_seen":    device.last_seen,
                    "status":       device.status,
                    "notes":        device.notes,
                })

                # Always update last_seen and increment msg_count
                conn.execute("""
                    UPDATE devices
                    SET last_seen  = :last_seen,
                        last_log_at = :last_seen,
                        msg_count   = msg_count + 1,
                        status      = 'online',
                        hostname    = CASE
                                        WHEN :hostname != '' THEN :hostname
                                        ELSE hostname
                                      END,
                        updated_at  = strftime('%Y-%m-%d %H:%M:%S','now')
                    WHERE ip = :ip
                """, {"ip": device.ip, "last_seen": device.last_seen,
                      "hostname": device.hostname})

        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Device upsert failed for {device.ip}: {exc}") from exc

    def update_device_ping(
        self,
        ip: str,
        reachable: bool,
        rtt_ms: float | None
    ) -> None:
        """
        Update a device's ping status after a sonar probe.

        Args:
            ip:        Device IP address.
            reachable: True if ICMP ping succeeded.
            rtt_ms:    Round-trip time in milliseconds, or None on failure.

        Raises:
            WriteError: If the update fails.
        """
        try:
            with self._vault.connection() as conn:
                conn.execute("""
                    UPDATE devices
                    SET ping_status = :status,
                        ping_rtt_ms = :rtt,
                        last_ping   = strftime('%Y-%m-%d %H:%M:%S','now'),
                        updated_at  = strftime('%Y-%m-%d %H:%M:%S','now')
                    WHERE ip = :ip
                """, {
                    "ip":     ip,
                    "status": "reachable" if reachable else "unreachable",
                    "rtt":    rtt_ms,
                })
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Ping update failed for {ip}: {exc}") from exc

    def update_device_status(self, ip: str, status: str) -> None:
        """
        Update a device's online/silent/offline status.

        Args:
            ip:     Device IP address.
            status: New status string (online/silent/offline/unknown).
        """
        try:
            with self._vault.connection() as conn:
                conn.execute("""
                    UPDATE devices
                    SET status     = :status,
                        updated_at = strftime('%Y-%m-%d %H:%M:%S','now')
                    WHERE ip = :ip
                """, {"ip": ip, "status": status})
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Status update failed for {ip}: {exc}") from exc

    # ── Alert writes ──────────────────────────────────────────────────────────

    def write_alert(self, alert: AlertRecord) -> int:
        """
        Insert a fired alert into alert_history.

        Args:
            alert: AlertRecord describing the fired condition.

        Returns:
            Row ID of the new alert history entry.

        Raises:
            WriteError: If the insert fails.
        """
        try:
            with self._vault.connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO alert_history
                        (rule_id, rule_name, level, reason, fired_at,
                         log_table, log_id, device_ip)
                    VALUES
                        (:rule_id, :rule_name, :level, :reason, :fired_at,
                         :log_table, :log_id, :device_ip)
                """, {
                    "rule_id":   alert.rule_id,
                    "rule_name": alert.rule_name,
                    "level":     alert.level,
                    "reason":    alert.reason,
                    "fired_at":  alert.fired_at,
                    "log_table": "",
                    "log_id":    alert.log_id,
                    "device_ip": alert.device_ip,
                })
                # Update fire count on the rule itself
                conn.execute("""
                    UPDATE alert_rules
                    SET fire_count = fire_count + 1,
                        last_fired  = :fired_at
                    WHERE id = :rule_id
                """, {"rule_id": alert.rule_id, "fired_at": alert.fired_at})

                metrics.dispatch_alerts_fired.increment()
                return cursor.lastrowid

        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Alert write failed: {exc}") from exc

    def acknowledge_alert(self, alert_id: int, ack_by: str) -> None:
        """
        Mark an alert as acknowledged.

        Args:
            alert_id: Primary key of the alert_history row.
            ack_by:   Username of the acknowledging user.

        Raises:
            WriteError: If the update fails.
        """
        try:
            with self._vault.connection() as conn:
                conn.execute("""
                    UPDATE alert_history
                    SET acknowledged = 1,
                        ack_by       = :ack_by,
                        ack_at       = strftime('%Y-%m-%d %H:%M:%S','now')
                    WHERE id = :id AND acknowledged = 0
                """, {"id": alert_id, "ack_by": ack_by})
                metrics.dispatch_alerts_acked.increment()
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Alert acknowledge failed: {exc}") from exc

    def resolve_alert(self, alert_id: int, notes: str = "") -> None:
        """
        Mark an alert as resolved — the terminal state in the
        open -> acknowledged -> resolved lifecycle dispatch/incident.py
        manages. An alert can be resolved directly from 'open' too
        (acknowledgement isn't a hard prerequisite).

        Args:
            alert_id: Primary key of the alert_history row.
            notes:    Optional resolution notes (root cause, action taken).

        Raises:
            WriteError: If the update fails.
        """
        try:
            with self._vault.connection() as conn:
                conn.execute("""
                    UPDATE alert_history
                    SET resolved    = 1,
                        resolved_at = strftime('%Y-%m-%d %H:%M:%S','now'),
                        notes       = CASE WHEN :notes != '' THEN :notes ELSE notes END
                    WHERE id = :id AND resolved = 0
                """, {"id": alert_id, "notes": notes})
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Alert resolve failed: {exc}") from exc

    # ── Alert rules (dispatch/rulebook.py) ──────────────────────────────────────

    def create_alert_rule(
        self, name: str, description: str, condition_json: str,
        action_json: str, level: str = "medium", enabled: bool = True,
        builtin: bool = False,
    ) -> int:
        """
        Insert a new alert rule definition.

        Args:
            name:           Unique rule name.
            description:    Human-readable summary.
            condition_json: JSON-encoded condition spec (see
                            dispatch/rulebook.py for the schema).
            action_json:    JSON-encoded action spec (notify channels, etc.).
            level:          Alert level this rule fires at.
            enabled:        Whether the rule is active immediately.
            builtin:        True for rules shipped with WATCHTOWER itself —
                            protects them from accidental deletion in the UI.

        Returns:
            Row ID of the new rule.

        Raises:
            WriteError: If the insert fails (e.g. duplicate name).
        """
        try:
            with self._vault.connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO alert_rules
                        (name, description, condition_json, action_json,
                         level, enabled, builtin)
                    VALUES
                        (:name, :description, :condition_json, :action_json,
                         :level, :enabled, :builtin)
                """, {
                    "name": name, "description": description,
                    "condition_json": condition_json, "action_json": action_json,
                    "level": level, "enabled": 1 if enabled else 0,
                    "builtin": 1 if builtin else 0,
                })
                return cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise WriteError(f"Alert rule '{name}' already exists: {exc}") from exc
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Alert rule creation failed: {exc}") from exc

    def update_alert_rule(
        self, rule_id: int, description: str | None = None,
        condition_json: str | None = None, action_json: str | None = None,
        level: str | None = None,
    ) -> None:
        """
        Update an existing alert rule. Only fields passed as non-None
        are changed. Does not touch `enabled` — use set_rule_enabled()
        for that so enable/disable stays a single, auditable operation.

        Raises:
            WriteError: If the update fails.
        """
        fields, params = [], {"id": rule_id}
        if description is not None:
            fields.append("description = :description")
            params["description"] = description
        if condition_json is not None:
            fields.append("condition_json = :condition_json")
            params["condition_json"] = condition_json
        if action_json is not None:
            fields.append("action_json = :action_json")
            params["action_json"] = action_json
        if level is not None:
            fields.append("level = :level")
            params["level"] = level

        if not fields:
            return  # nothing to update

        fields.append("updated_at = strftime('%Y-%m-%d %H:%M:%S','now')")
        sql = f"UPDATE alert_rules SET {', '.join(fields)} WHERE id = :id"
        try:
            with self._vault.connection() as conn:
                conn.execute(sql, params)
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Alert rule update failed for id={rule_id}: {exc}") from exc

    def set_rule_enabled(self, rule_id: int, enabled: bool) -> None:
        """Enable or disable a rule without touching its condition/action."""
        try:
            with self._vault.connection() as conn:
                conn.execute("""
                    UPDATE alert_rules
                    SET enabled = :enabled,
                        updated_at = strftime('%Y-%m-%d %H:%M:%S','now')
                    WHERE id = :id
                """, {"id": rule_id, "enabled": 1 if enabled else 0})
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Rule enable/disable failed for id={rule_id}: {exc}") from exc

    def delete_alert_rule(self, rule_id: int) -> None:
        """
        Delete an alert rule. Refuses to delete builtin rules — disable
        them with set_rule_enabled() instead.

        Raises:
            WriteError: If the rule is builtin, or the delete fails.
        """
        try:
            with self._vault.connection() as conn:
                row = conn.execute(
                    "SELECT builtin FROM alert_rules WHERE id = :id", {"id": rule_id}
                ).fetchone()
                if row and row["builtin"]:
                    raise WriteError(f"Refusing to delete builtin rule id={rule_id} — disable it instead")
                conn.execute("DELETE FROM alert_rules WHERE id = :id", {"id": rule_id})
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Alert rule delete failed for id={rule_id}: {exc}") from exc

    # ── Audit trail ───────────────────────────────────────────────────────────

    def write_audit(
        self,
        actor: str,
        action: str,
        target: str,
        detail: str = "",
        ip_address: str = "",
        user_agent: str = "",
        result: str = "success",
        session_id: str = "",
    ) -> None:
        """
        Write a single entry to the tamper-evident audit trail.

        Args:
            actor:      Username or system component that performed the action.
            action:     What was done (e.g. 'login', 'config_change').
            target:     What was acted upon (e.g. 'alert_rules', 'password').
            detail:     Optional additional context.
            ip_address: Source IP of the actor.
            user_agent: Browser/client user-agent string.
            result:     'success' or 'failure'.
            session_id: Session token reference.

        Raises:
            WriteError: If the insert fails.
        """
        try:
            with self._vault.connection() as conn:
                conn.execute("""
                    INSERT INTO audit_trail
                        (actor, action, target, detail,
                         ip_address, user_agent, result, session_id)
                    VALUES
                        (:actor, :action, :target, :detail,
                         :ip_address, :user_agent, :result, :session_id)
                """, {
                    "actor":      actor,
                    "action":     action,
                    "target":     target,
                    "detail":     detail,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "result":     result,
                    "session_id": session_id,
                })
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            # Audit failures are logged but not raised —
            # we must not crash the server because audit logging failed
            logger.error("AUDIT WRITE FAILED: %s | %s | %s | %s", actor, action, target, exc)

    # ── Intake stats snapshot ─────────────────────────────────────────────────

    def write_intake_snapshot(self) -> None:
        """
        Write current telemetry counters to the intake_stats table.
        Called by the scheduler every minute for historical trending.
        """
        snap = metrics.snapshot()
        try:
            with self._vault.connection() as conn:
                conn.execute("""
                    INSERT INTO intake_stats
                        (packets_received, packets_dropped, bytes_received,
                         queue_depth, parse_errors, db_write_errors)
                    VALUES
                        (:packets_received, :packets_dropped, :bytes_received,
                         :queue_depth, :parse_errors, :db_write_errors)
                """, {
                    "packets_received": snap["intake"]["packets_received"],
                    "packets_dropped":  snap["intake"]["packets_dropped"],
                    "bytes_received":   snap["intake"]["bytes_received"],
                    "queue_depth":      snap["intake"]["queue_depth"],
                    "parse_errors":     snap["pipeline"]["parse_errors"],
                    "db_write_errors":  snap["ledger"]["write_errors"],
                })
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            logger.warning("Intake snapshot write failed: %s", exc)

    # ── Failover / HA writes ──────────────────────────────────────────────────

    def write_failover_event(
        self,
        event_type: str,
        from_server: str = "",
        to_server: str = "",
        virtual_ip: str = "",
        duration_sec: float | None = None,
        detail: str = "",
    ) -> int:
        """
        Insert a single HA event into failover_log.

        Called by relay/failover_log.py — never call this directly from
        heartbeat.py/consensus.py/replicator.py, route through
        FailoverLog so event_type stays within its known vocabulary.

        Args:
            event_type:   e.g. 'promotion', 'demotion', 'split_brain_averted',
                          'replication_restored', 'replication_lag_warning'.
            from_server:  Hostname/IP relinquishing the role, if applicable.
            to_server:    Hostname/IP taking on the role, if applicable.
            virtual_ip:   The VIP involved, if applicable.
            duration_sec: How long the transition took, if measured.
            detail:       Free-text context (reason, consensus check results).

        Returns:
            Row ID of the new failover_log entry.

        Raises:
            WriteError: If the insert fails.
        """
        try:
            with self._vault.connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO failover_log
                        (event_type, from_server, to_server, virtual_ip,
                         duration_sec, detail)
                    VALUES
                        (:event_type, :from_server, :to_server, :virtual_ip,
                         :duration_sec, :detail)
                """, {
                    "event_type":   event_type,
                    "from_server":  from_server,
                    "to_server":    to_server,
                    "virtual_ip":   virtual_ip,
                    "duration_sec": duration_sec,
                    "detail":       detail,
                })
                return cursor.lastrowid
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            raise WriteError(f"Failover event write failed: {exc}") from exc

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _record_to_params(record: LogRecord) -> dict:
        """
        Convert a LogRecord to a parameter dict for SQL insertion.
        Boolean is_threat is converted to SQLite integer (0/1).

        Args:
            record: The LogRecord to convert.

        Returns:
            Dict mapping column names to values.
        """
        return {
            "timestamp":      record.timestamp,
            "received_at":    record.received_at,
            "facility":       record.facility,
            "severity":       record.severity,
            "hostname":       record.hostname,
            "sender_ip":      record.sender_ip,
            "sender_port":    record.sender_port,
            "app_name":       record.app_name,
            "proc_id":        record.proc_id,
            "msg_id":         record.msg_id,
            "message":        record.message,
            "raw_message":    record.raw_message,
            "format":         record.format,
            "log_category":   record.log_category,
            "device_type":    record.device_type,
            "transport":      record.transport,
            "source_ip":      record.source_ip,
            "dest_ip":        record.dest_ip,
            "source_port":    record.source_port,
            "dest_port":      record.dest_port,
            "protocol":       record.protocol,
            "username":       record.username,
            "action":         record.action,
            "event_type":     record.event_type,
            "geo_country":    record.geo_country,
            "geo_city":       record.geo_city,
            "geo_isp":        record.geo_isp,
            "is_threat":      1 if record.is_threat else 0,
            "threat_score":   record.threat_score,
            "rdns":           record.rdns,
            "integrity_hash": record.integrity_hash,
        }