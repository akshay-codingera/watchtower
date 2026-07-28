"""
ledger/retention.py
===================
WATCHTOWER — Log Retention and Database Maintenance

Enforces configurable retention policies by deleting log records
older than the configured threshold per category.

After deletion, runs VACUUM to reclaim disk space and updates
statistics so the dashboard shows accurate counts.

Design:
    Retention runs as a scheduled job at a quiet hour (default 03:00).
    It deletes in batches to avoid holding a write lock for too long.
    Each batch is a separate transaction so other writers are not
    blocked for the full duration of a large purge.

    Retention periods are configured in config.ini per category:
        [ledger]
        retention_auth_days      = 90
        retention_network_days   = 60
        retention_firewall_days  = 90
        retention_system_days    = 30
        retention_app_days       = 30
"""

from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field

from nucleus.constants import CATEGORY_TABLE, LogCategory
from nucleus.exceptions import LedgerError
from ledger.vault import Vault

logger = logging.getLogger(__name__)

# Rows deleted per batch transaction — keeps write locks short
_BATCH_SIZE = 5000


@dataclass
class RetentionResult:
    """
    Summary of a single retention run.
    Returned by RetentionManager.run() and logged + stored.
    """
    started_at:     str   = ""
    finished_at:    str   = ""
    duration_sec:   float = 0.0
    rows_deleted:   dict  = field(default_factory=dict)   # category → count
    total_deleted:  int   = 0
    size_before_mb: float = 0.0
    size_after_mb:  float = 0.0
    space_freed_mb: float = 0.0
    vacuumed:       bool  = False
    errors:         list  = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "started_at":    self.started_at,
            "finished_at":   self.finished_at,
            "duration_sec":  round(self.duration_sec, 2),
            "rows_deleted":  self.rows_deleted,
            "total_deleted": self.total_deleted,
            "size_before_mb": self.size_before_mb,
            "size_after_mb":  self.size_after_mb,
            "space_freed_mb": self.space_freed_mb,
            "vacuumed":      self.vacuumed,
            "errors":        self.errors,
        }


class RetentionManager:
    """
    Enforces log retention policies and reclaims disk space.

    Args:
        vault:          Initialised Vault instance.
        retention_days: Dict mapping category name to retention days.
                        e.g. {"auth": 90, "system": 30}
        db_path:        Path to the SQLite file (for size reporting).
    """

    def __init__(
        self,
        vault: Vault,
        retention_days: dict[str, int],
        db_path: str,
    ) -> None:
        self._vault          = vault
        self._retention_days = retention_days
        self._db_path        = db_path

    def run(self, vacuum: bool = True) -> RetentionResult:
        """
        Execute a full retention run across all log categories.

        For each category, deletes all rows with received_at older
        than the configured retention period in batches of _BATCH_SIZE.

        Args:
            vacuum: If True, run VACUUM after deletion to reclaim disk space.
                    VACUUM rewrites the entire database — slow but thorough.
                    Set False for a quick nightly pass; True for weekly.

        Returns:
            RetentionResult with counts and sizes.
        """
        import datetime
        from pathlib import Path

        result               = RetentionResult()
        result.started_at    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        t_start              = time.perf_counter()

        # Capture size before
        db_file              = Path(self._db_path)
        result.size_before_mb = self._file_size_mb(db_file)

        logger.info("Retention run started — db size: %.2f MB", result.size_before_mb)

        # Delete per category
        for category in LogCategory.ALL:
            days  = self._retention_days.get(category, 30)
            table = CATEGORY_TABLE.get(category)
            if not table:
                continue
            try:
                deleted = self._purge_category(table, days)
                result.rows_deleted[category] = deleted
                result.total_deleted         += deleted
                logger.info(
                    "Retention: %s — deleted %d rows older than %d days",
                    category, deleted, days
                )
            except Exception as exc:
                msg = f"Retention failed for {category}: {exc}"
                logger.error(msg)
                result.errors.append(msg)

        # Also purge old audit trail entries (keep 1 year)
        try:
            audit_deleted = self._purge_table("audit_trail", 365, "timestamp")
            if audit_deleted:
                logger.info("Retention: audit_trail — deleted %d rows", audit_deleted)
        except Exception as exc:
            logger.warning("Audit trail retention failed: %s", exc)

        # Also purge old intake_stats (keep 90 days)
        try:
            self._purge_table("intake_stats", 90, "recorded_at")
        except Exception as exc:
            logger.warning("Intake stats retention failed: %s", exc)

        # VACUUM to reclaim freed pages
        if vacuum and result.total_deleted > 0:
            try:
                self._vacuum()
                result.vacuumed = True
            except Exception as exc:
                msg = f"VACUUM failed: {exc}"
                logger.warning(msg)
                result.errors.append(msg)

        # Capture size after
        result.size_after_mb  = self._file_size_mb(db_file)
        result.space_freed_mb = round(
            result.size_before_mb - result.size_after_mb, 2
        )
        result.duration_sec   = time.perf_counter() - t_start
        result.finished_at    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        logger.info(
            "Retention complete: %d rows deleted, %.2f MB freed in %.1fs",
            result.total_deleted,
            result.space_freed_mb,
            result.duration_sec,
        )
        return result

    def dry_run(self) -> dict[str, int]:
        """
        Count rows that WOULD be deleted without deleting anything.
        Safe to call at any time for reporting or confirmation.

        Returns:
            Dict mapping category name to row count eligible for deletion.
        """
        counts: dict[str, int] = {}
        conn = self._vault.get_connection()

        for category in LogCategory.ALL:
            days  = self._retention_days.get(category, 30)
            table = CATEGORY_TABLE.get(category)
            if not table:
                continue
            try:
                cutoff = self._cutoff_datetime(days)
                row    = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE received_at < :cutoff",
                    {"cutoff": cutoff}
                ).fetchone()
                counts[category] = row[0] if row else 0
            except sqlite3.Error as exc:
                logger.warning("Dry-run count failed for %s: %s", category, exc)
                counts[category] = -1

        return counts

    def db_stats(self) -> dict:
        """
        Return current database statistics for the settings page.

        Returns:
            Dict with size_mb, row counts per table, oldest entry dates.
        """
        from pathlib import Path

        conn    = self._vault.get_connection()
        stats: dict = {
            "size_mb":      self._file_size_mb(Path(self._db_path)),
            "tables":       {},
            "oldest_entry": {},
        }

        for category, table in CATEGORY_TABLE.items():
            try:
                count = conn.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
                oldest = conn.execute(
                    f"SELECT MIN(received_at) FROM {table}"
                ).fetchone()[0]
                stats["tables"][table]       = count
                stats["oldest_entry"][table] = oldest or "—"
            except sqlite3.Error:
                stats["tables"][table]       = 0
                stats["oldest_entry"][table] = "—"

        stats["total_rows"] = sum(stats["tables"].values())
        return stats

    # ── Private helpers ───────────────────────────────────────────────────────

    def _purge_category(self, table: str, days: int) -> int:
        """
        Delete rows from a log table older than `days` in batches.

        Batching prevents holding a write lock for the entire duration
        of a large purge. Each batch is a separate transaction.

        Args:
            table: Log table name.
            days:  Retention period in days.

        Returns:
            Total number of rows deleted.
        """
        cutoff  = self._cutoff_datetime(days)
        total   = 0

        while True:
            try:
                with self._vault.connection() as conn:
                    cursor = conn.execute(f"""
                        DELETE FROM {table}
                        WHERE id IN (
                            SELECT id FROM {table}
                            WHERE received_at < :cutoff
                            LIMIT :batch
                        )
                    """, {"cutoff": cutoff, "batch": _BATCH_SIZE})
                    deleted = cursor.rowcount

                total += deleted
                if deleted < _BATCH_SIZE:
                    break   # last batch — all eligible rows deleted

                # Brief pause between batches to yield to writers
                time.sleep(0.05)

            except sqlite3.OperationalError as exc:
                if "database is locked" in str(exc):
                    logger.warning("DB locked during retention — retrying in 2s")
                    time.sleep(2)
                    continue
                raise LedgerError(f"Retention purge failed on {table}: {exc}") from exc

        return total

    def _purge_table(
        self, table: str, days: int, timestamp_col: str = "created_at"
    ) -> int:
        """Delete rows from any table (not just log tables) older than days."""
        cutoff = self._cutoff_datetime(days)
        try:
            with self._vault.connection() as conn:
                cursor = conn.execute(
                    f"DELETE FROM {table} WHERE {timestamp_col} < :cutoff",
                    {"cutoff": cutoff}
                )
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise LedgerError(f"Purge failed on {table}: {exc}") from exc

    def _vacuum(self) -> None:
        """
        Run VACUUM on the database to reclaim freed page space.

        VACUUM cannot run inside a transaction. We get a raw connection
        and set isolation_level back to default for this operation.
        """
        logger.info("Running VACUUM — this may take a moment on large databases")
        t = time.perf_counter()
        conn = self._vault.get_connection()
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.execute("VACUUM")
            elapsed = time.perf_counter() - t
            logger.info("VACUUM completed in %.1fs", elapsed)
        except sqlite3.Error as exc:
            raise LedgerError(f"VACUUM failed: {exc}") from exc

    @staticmethod
    def _cutoff_datetime(days: int) -> str:
        """Return an ISO datetime string `days` ago from now (UTC)."""
        import datetime
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
        return cutoff.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _file_size_mb(path) -> float:
        """Return file size in MB, or 0.0 if file does not exist."""
        from pathlib import Path
        p = Path(path)
        if p.exists():
            return round(p.stat().st_size / 1_048_576, 2)
        return 0.0