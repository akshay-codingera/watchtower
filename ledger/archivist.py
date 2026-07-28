"""
ledger/archivist.py
===================
WATCHTOWER — Read Layer

The archivist is responsible exclusively for reading from the database.
It never writes. It provides typed, paginated, filterable query methods
for the dashboard API.

Every public method returns plain Python dicts or lists of dicts —
never raw sqlite3.Row objects. This keeps the portal layer decoupled
from the database implementation.

Query safety: all WHERE clauses use parameterized queries.
No SQL string concatenation anywhere in this file.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Optional

from nucleus.constants import CATEGORY_TABLE, LogCategory
from nucleus.exceptions import ReadError
from ledger.vault import Vault

logger = logging.getLogger(__name__)

# ── Query filter dataclass ────────────────────────────────────────────────────

@dataclass
class LogFilter:
    """
    Typed filter specification for log queries.

    All fields are optional. Unset fields are not applied as WHERE conditions.
    This is the single object passed between the portal API and archivist
    so the query interface is stable even as filter options expand.

    Usage:
        f = LogFilter(severity="ERROR", hostname="webserver-01", limit=50)
        rows = archivist.fetch_logs(f)
    """
    severity:     Optional[str]  = None    # e.g. "ERROR"
    facility:     Optional[str]  = None    # e.g. "auth"
    hostname:     Optional[str]  = None    # exact or partial match
    sender_ip:    Optional[str]  = None    # exact match
    app_name:     Optional[str]  = None    # partial match
    log_category: Optional[str]  = None    # auth/network/firewall/system/app
    device_type:  Optional[str]  = None    # exact match
    action:       Optional[str]  = None    # allow/block/deny
    event_type:   Optional[str]  = None    # partial match
    username:     Optional[str]  = None    # partial match
    keyword:      Optional[str]  = None    # full-text search via FTS5
    from_time:    Optional[str]  = None    # ISO datetime string
    to_time:      Optional[str]  = None    # ISO datetime string
    is_threat:    Optional[bool] = None    # True = only threat IPs
    limit:        int            = 100
    offset:       int            = 0
    order_by:     str            = "received_at"
    order_dir:    str            = "DESC"   # ASC or DESC

    def validate(self) -> None:
        """Raise ValueError on obviously invalid filter values."""
        if self.limit < 1 or self.limit > 5000:
            raise ValueError(f"limit must be 1–5000, got {self.limit}")
        if self.offset < 0:
            raise ValueError(f"offset must be >= 0, got {self.offset}")
        allowed_order = {"received_at", "timestamp", "severity", "hostname", "id"}
        if self.order_by not in allowed_order:
            raise ValueError(f"order_by must be one of {allowed_order}")
        if self.order_dir not in ("ASC", "DESC"):
            raise ValueError("order_dir must be ASC or DESC")


class Archivist:
    """
    Read-only interface to the WATCHTOWER ledger.

    Args:
        vault: Initialised Vault instance providing database connections.
    """

    def __init__(self, vault: Vault) -> None:
        self._vault = vault

    # ── Primary log queries ───────────────────────────────────────────────────

    def fetch_logs(self, log_filter: LogFilter) -> list[dict]:
        """
        Fetch log records matching the given filter.

        Queries the all_logs view unless log_category is specified,
        in which case it queries the specific category table directly
        (faster — avoids the UNION).

        Args:
            log_filter: LogFilter specifying all query constraints.

        Returns:
            List of dicts, each representing one log row.

        Raises:
            ReadError: If the query fails.
        """
        log_filter.validate()

        # If keyword search requested and FTS available, route to FTS
        if log_filter.keyword:
            return self._fetch_via_fts(log_filter)

        # Choose source table / view
        if log_filter.log_category and log_filter.log_category in CATEGORY_TABLE:
            source = CATEGORY_TABLE[log_filter.log_category]
        else:
            source = "all_logs"

        where_clauses: list[str] = []
        params: dict[str, Any]   = {}

        self._apply_filter(log_filter, where_clauses, params)

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        order_sql = f"ORDER BY {log_filter.order_by} {log_filter.order_dir}"
        limit_sql = "LIMIT :limit OFFSET :offset"
        params["limit"]  = log_filter.limit
        params["offset"] = log_filter.offset

        sql = f"SELECT * FROM {source} {where_sql} {order_sql} {limit_sql}"

        return self._execute_select(sql, params)

    def fetch_by_id(self, log_id: int, table: str) -> Optional[dict]:
        """
        Fetch a single log record by its primary key from a specific table.

        Args:
            log_id: Primary key (id column) of the log record.
            table:  Table name (e.g. 'auth_logs', 'system_logs').

        Returns:
            Dict of the row, or None if not found.

        Raises:
            ReadError: If the table name is invalid or query fails.
        """
        valid_tables = set(CATEGORY_TABLE.values()) | {"all_logs"}
        if table not in valid_tables:
            raise ReadError(f"Unknown table: {table!r}")

        rows = self._execute_select(
            f"SELECT * FROM {table} WHERE id = :id LIMIT 1",
            {"id": log_id}
        )
        return rows[0] if rows else None

    def fetch_latest(self, limit: int = 100, category: str | None = None) -> list[dict]:
        """
        Fetch the most recent log records across all categories.

        Args:
            limit:    Maximum number of records to return (max 1000).
            category: Optional category to filter to a single table.

        Returns:
            List of log record dicts, newest first.
        """
        limit   = min(limit, 1000)
        source  = CATEGORY_TABLE.get(category, "all_logs") if category else "all_logs"
        return self._execute_select(
            f"SELECT * FROM {source} ORDER BY received_at DESC LIMIT :limit",
            {"limit": limit}
        )

    def count_logs(self, log_filter: LogFilter) -> int:
        """
        Count total records matching a filter (for pagination).

        Args:
            log_filter: Same filter as used in fetch_logs.

        Returns:
            Integer count of matching rows.
        """
        if log_filter.log_category and log_filter.log_category in CATEGORY_TABLE:
            source = CATEGORY_TABLE[log_filter.log_category]
        else:
            source = "all_logs"

        where_clauses: list[str] = []
        params: dict[str, Any]   = {}
        self._apply_filter(log_filter, where_clauses, params)
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        rows = self._execute_select(
            f"SELECT COUNT(*) AS cnt FROM {source} {where_sql}", params
        )
        return rows[0]["cnt"] if rows else 0

    # ── Statistics queries (for dashboard cards and analytics) ────────────────

    def stats_severity_breakdown(
        self, hours: int = 24, category: str | None = None
    ) -> list[dict]:
        """
        Count log records grouped by severity in the last N hours.

        Args:
            hours:    Look-back window in hours.
            category: Optional category table to restrict to.

        Returns:
            List of {severity, count} dicts, ordered by severity code.
        """
        source = CATEGORY_TABLE.get(category, "all_logs") if category else "all_logs"
        return self._execute_select("""
            SELECT severity, COUNT(*) AS count
            FROM {src}
            WHERE received_at >= datetime('now', :window)
            GROUP BY severity
            ORDER BY count DESC
        """.format(src=source), {"window": f"-{hours} hours"})

    def stats_hourly_volume(self, hours: int = 24) -> list[dict]:
        """
        Count log records per hour for the last N hours.

        Args:
            hours: Number of hours to look back (max 168 = 7 days).

        Returns:
            List of {hour, count} dicts ordered by hour ascending.
        """
        hours = min(hours, 168)
        return self._execute_select("""
            SELECT strftime('%Y-%m-%d %H:00', received_at) AS hour,
                   COUNT(*) AS count
            FROM all_logs
            WHERE received_at >= datetime('now', :window)
            GROUP BY hour
            ORDER BY hour ASC
        """, {"window": f"-{hours} hours"})

    def stats_top_sources(self, limit: int = 10, hours: int = 24) -> list[dict]:
        """
        Return the top N senders by message count.

        Args:
            limit: Number of top sources to return.
            hours: Look-back window.

        Returns:
            List of {sender_ip, hostname, count} dicts.
        """
        return self._execute_select("""
            SELECT sender_ip, hostname, COUNT(*) AS count
            FROM all_logs
            WHERE received_at >= datetime('now', :window)
            GROUP BY sender_ip
            ORDER BY count DESC
            LIMIT :limit
        """, {"window": f"-{hours} hours", "limit": limit})

    def stats_device_type_breakdown(self, hours: int = 24) -> list[dict]:
        """Count logs per device type."""
        return self._execute_select("""
            SELECT device_type, COUNT(*) AS count
            FROM all_logs
            WHERE received_at >= datetime('now', :window)
            GROUP BY device_type
            ORDER BY count DESC
        """, {"window": f"-{hours} hours"})

    def stats_category_totals(self) -> dict[str, int]:
        """
        Return total row counts per category table.

        Returns:
            Dict mapping category name to total row count.
        """
        totals: dict[str, int] = {}
        for category, table in CATEGORY_TABLE.items():
            rows = self._execute_select(
                f"SELECT COUNT(*) AS cnt FROM {table}", {}
            )
            totals[category] = rows[0]["cnt"] if rows else 0
        return totals

    def stats_summary(self, hours: int = 24) -> dict:
        """
        Single-call summary for the dashboard header cards.

        Returns:
            Dict with total, errors, warnings, critical, sources,
            new_devices counts for the last N hours.
        """
        rows = self._execute_select("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN severity IN ('EMERG','ALERT','CRIT') THEN 1 ELSE 0 END) AS critical,
                SUM(CASE WHEN severity = 'ERROR'   THEN 1 ELSE 0 END) AS errors,
                SUM(CASE WHEN severity = 'WARNING' THEN 1 ELSE 0 END) AS warnings,
                COUNT(DISTINCT sender_ip) AS sources
            FROM all_logs
            WHERE received_at >= datetime('now', :window)
        """, {"window": f"-{hours} hours"})

        row = rows[0] if rows else {}
        return {
            "total":    row.get("total", 0)    or 0,
            "critical": row.get("critical", 0) or 0,
            "errors":   row.get("errors", 0)   or 0,
            "warnings": row.get("warnings", 0) or 0,
            "sources":  row.get("sources", 0)  or 0,
        }

    # ── Device queries ────────────────────────────────────────────────────────

    def fetch_devices(
        self, status: str | None = None, device_type: str | None = None
    ) -> list[dict]:
        """
        Fetch all known devices from the registry.

        Args:
            status:      Optional filter: 'online'/'offline'/'silent'.
            device_type: Optional filter by device type string.

        Returns:
            List of device dicts ordered by last_seen descending.
        """
        where_clauses: list[str] = []
        params: dict[str, Any]   = {}

        if status:
            where_clauses.append("status = :status")
            params["status"] = status
        if device_type:
            where_clauses.append("device_type = :device_type")
            params["device_type"] = device_type

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        return self._execute_select(
            f"SELECT * FROM devices {where_sql} ORDER BY last_seen DESC",
            params
        )

    def fetch_device(self, ip: str) -> Optional[dict]:
        """Fetch a single device by IP address."""
        rows = self._execute_select(
            "SELECT * FROM devices WHERE ip = :ip LIMIT 1",
            {"ip": ip}
        )
        return rows[0] if rows else None

    def fetch_device_logs(
        self, ip: str, limit: int = 100, hours: int = 24
    ) -> list[dict]:
        """
        Fetch recent logs sent by a specific device.

        Args:
            ip:    Device IP address.
            limit: Maximum number of records.
            hours: Look-back window.

        Returns:
            List of log dicts from this device.
        """
        return self._execute_select("""
            SELECT * FROM all_logs
            WHERE sender_ip = :ip
              AND received_at >= datetime('now', :window)
            ORDER BY received_at DESC
            LIMIT :limit
        """, {"ip": ip, "window": f"-{hours} hours", "limit": limit})

    # ── Alert queries ─────────────────────────────────────────────────────────

    def fetch_alerts(
        self,
        acknowledged: bool | None = None,
        resolved: bool | None = None,
        level: str | None = None,
        limit: int = 50
    ) -> list[dict]:
        """
        Fetch alert history records.

        Args:
            acknowledged: If True/False, filter by ack status. None = all.
            resolved:     If True/False, filter by resolved status. None = all.
                          Pass resolved=False to get the "open incidents"
                          view dispatch/incident.py's default queries want.
            level:        Filter by alert level string.
            limit:        Maximum records to return.

        Returns:
            List of alert history dicts, newest first.
        """
        where_clauses: list[str] = []
        params: dict[str, Any]   = {"limit": limit}

        if acknowledged is not None:
            where_clauses.append("acknowledged = :acked")
            params["acked"] = 1 if acknowledged else 0
        if resolved is not None:
            where_clauses.append("resolved = :resolved")
            params["resolved"] = 1 if resolved else 0
        if level:
            where_clauses.append("level = :level")
            params["level"] = level

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        return self._execute_select(
            f"SELECT * FROM alert_history {where_sql} ORDER BY fired_at DESC LIMIT :limit",
            params
        )

    def fetch_alert_rules(self, enabled_only: bool = False) -> list[dict]:
        """Fetch all alert rules."""
        where = "WHERE enabled = 1" if enabled_only else ""
        return self._execute_select(
            f"SELECT * FROM alert_rules {where} ORDER BY name ASC", {}
        )

    def fetch_alert_rule(self, rule_id: int | None = None, name: str | None = None) -> Optional[dict]:
        """
        Fetch a single alert rule by id or name (exactly one must be given).

        Args:
            rule_id: Primary key lookup.
            name:    Exact name lookup — alert_rules.name is UNIQUE.

        Returns:
            The rule dict, or None if not found.

        Raises:
            ReadError: If neither or both of rule_id/name are given.
        """
        if (rule_id is None) == (name is None):
            raise ReadError("fetch_alert_rule requires exactly one of rule_id or name")

        if rule_id is not None:
            rows = self._execute_select(
                "SELECT * FROM alert_rules WHERE id = :id LIMIT 1", {"id": rule_id}
            )
        else:
            rows = self._execute_select(
                "SELECT * FROM alert_rules WHERE name = :name LIMIT 1", {"name": name}
            )
        return rows[0] if rows else None

    # ── Audit trail ───────────────────────────────────────────────────────────

    def fetch_audit_trail(
        self, limit: int = 200, actor: str | None = None
    ) -> list[dict]:
        """
        Fetch audit trail entries.

        Args:
            limit: Maximum records.
            actor: Optional filter by actor username.

        Returns:
            List of audit trail dicts, newest first.
        """
        where_clauses: list[str] = []
        params: dict[str, Any]   = {"limit": limit}

        if actor:
            where_clauses.append("actor = :actor")
            params["actor"] = actor

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        return self._execute_select(
            f"SELECT * FROM audit_trail {where_sql} ORDER BY timestamp DESC LIMIT :limit",
            params
        )

    # ── Failover log ─────────────────────────────────────────────────────────

    def fetch_failover_log(
        self, limit: int = 100, event_type: str | None = None
    ) -> list[dict]:
        """
        Fetch relay/HA failover events.

        Args:
            limit:      Maximum records to return.
            event_type: Optional filter by exact event_type string.

        Returns:
            List of failover_log dicts, newest first.
        """
        where_clauses: list[str] = []
        params: dict[str, Any]   = {"limit": limit}

        if event_type:
            where_clauses.append("event_type = :event_type")
            params["event_type"] = event_type

        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        return self._execute_select(
            f"SELECT * FROM failover_log {where_sql} ORDER BY timestamp DESC LIMIT :limit",
            params
        )

    def last_failover_event(self) -> Optional[dict]:
        """Fetch the single most recent failover event, or None if there are none."""
        rows = self._execute_select(
            "SELECT * FROM failover_log ORDER BY timestamp DESC LIMIT 1", {}
        )
        return rows[0] if rows else None

    # ── Export ────────────────────────────────────────────────────────────────

    def export_logs(self, log_filter: LogFilter) -> list[dict]:
        """
        Fetch records for export. Raises limit to 50,000 for export use.

        Args:
            log_filter: Filter spec — limit is overridden to 50,000.

        Returns:
            List of log dicts for CSV/JSON/Excel export.
        """
        log_filter.limit  = 50_000
        log_filter.offset = 0
        return self.fetch_logs(log_filter)

    # ── FTS5 full-text search ─────────────────────────────────────────────────

    def _fetch_via_fts(self, log_filter: LogFilter) -> list[dict]:
        """
        Use FTS5 to find rows matching the keyword, then fetch full rows.

        The FTS table stores rowids that map to the content table.
        We query FTS for matching rowids, then SELECT the full rows.

        Args:
            log_filter: Filter with keyword set.

        Returns:
            List of matching log dicts.
        """
        keyword = log_filter.keyword or ""
        results: list[dict] = []

        # Determine which FTS tables to search
        fts_map = {
            "auth":     ("fts_auth",     "auth_logs"),
            "network":  ("fts_network",  "network_logs"),
            "firewall": ("fts_firewall", "firewall_logs"),
            "system":   ("fts_system",   "system_logs"),
            "app":      ("fts_app",      "app_logs"),
        }

        if log_filter.log_category and log_filter.log_category in fts_map:
            search_targets = {log_filter.log_category: fts_map[log_filter.log_category]}
        else:
            search_targets = fts_map

        per_table_limit = log_filter.limit // len(search_targets) + 10

        for category, (fts_table, log_table) in search_targets.items():
            try:
                rows = self._execute_select(f"""
                    SELECT l.*
                    FROM {log_table} l
                    JOIN {fts_table} f ON l.id = f.rowid
                    WHERE {fts_table} MATCH :kw
                    ORDER BY rank
                    LIMIT :limit
                """, {"kw": keyword, "limit": per_table_limit})
                results.extend(rows)
            except Exception as exc:
                logger.warning("FTS search failed on %s: %s", fts_table, exc)

        # Sort combined results by received_at descending, apply overall limit
        results.sort(key=lambda r: r.get("received_at", ""), reverse=True)
        return results[:log_filter.limit]

    # ── Private helpers ───────────────────────────────────────────────────────

    def _apply_filter(
        self,
        f: LogFilter,
        clauses: list[str],
        params: dict[str, Any],
    ) -> None:
        """
        Append WHERE clause fragments and params for each active filter field.
        Uses parameterized queries exclusively — no string interpolation.
        """
        if f.severity:
            clauses.append("severity = :severity")
            params["severity"] = f.severity

        if f.facility:
            clauses.append("facility = :facility")
            params["facility"] = f.facility

        if f.hostname:
            clauses.append("hostname LIKE :hostname")
            params["hostname"] = f"%{f.hostname}%"

        if f.sender_ip:
            clauses.append("sender_ip = :sender_ip")
            params["sender_ip"] = f.sender_ip

        if f.app_name:
            clauses.append("app_name LIKE :app_name")
            params["app_name"] = f"%{f.app_name}%"

        if f.device_type:
            clauses.append("device_type = :device_type")
            params["device_type"] = f.device_type

        if f.action:
            clauses.append("action = :action")
            params["action"] = f.action

        if f.event_type:
            clauses.append("event_type LIKE :event_type")
            params["event_type"] = f"%{f.event_type}%"

        if f.username:
            clauses.append("username LIKE :username")
            params["username"] = f"%{f.username}%"

        if f.from_time:
            clauses.append("received_at >= :from_time")
            params["from_time"] = f.from_time

        if f.to_time:
            clauses.append("received_at <= :to_time")
            params["to_time"] = f.to_time

        if f.is_threat is not None:
            clauses.append("is_threat = :is_threat")
            params["is_threat"] = 1 if f.is_threat else 0

    def _execute_select(self, sql: str, params: dict) -> list[dict]:
        """
        Execute a SELECT query and return rows as list of dicts.

        Args:
            sql:    Parameterized SQL string.
            params: Named parameter dict matching placeholders.

        Returns:
            List of row dicts (empty list if no rows found).

        Raises:
            ReadError: If the query fails.
        """
        try:
            conn = self._vault.get_connection()
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError as exc:
            raise ReadError(f"Query failed: {exc}\nSQL: {sql[:200]}") from exc