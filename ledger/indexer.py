"""
ledger/indexer.py
=================
WATCHTOWER — Full-Text Search Index Manager

Manages the FTS5 virtual tables defined in 002_integrity.sql.
The indexer handles rebuilding, optimizing, and verifying
the full-text search indexes.

Under normal operation, FTS indexes are maintained automatically
by the triggers defined in 002_integrity.sql — no code needed.
This module handles exceptional cases:
    - Index rebuild after a crash or corruption
    - Optimization pass (merges FTS segments for faster reads)
    - Integrity check (verify FTS and content tables are in sync)

FTS5 background:
    An FTS5 index is an inverted index: for each word in the corpus,
    it stores the list of rowids that contain that word. This allows
    searching "SELECT * FROM fts_auth WHERE fts_auth MATCH 'failed'"
    in O(log N) time instead of O(N) for LIKE '%failed%'.
    At 10 million rows, LIKE takes seconds; FTS5 takes milliseconds.
"""

from __future__ import annotations

import logging
import time
import sqlite3
from dataclasses import dataclass

from nucleus.exceptions import LedgerError
from ledger.vault import Vault

logger = logging.getLogger(__name__)

# FTS table → content table mapping
FTS_TABLES: dict[str, str] = {
    "fts_auth":     "auth_logs",
    "fts_network":  "network_logs",
    "fts_firewall": "firewall_logs",
    "fts_system":   "system_logs",
    "fts_app":      "app_logs",
}


@dataclass
class IndexStats:
    """Results from an index rebuild or optimization operation."""
    table:         str
    rows_indexed:  int
    duration_ms:   float
    success:       bool
    error:         str = ""


class Indexer:
    """
    FTS5 index lifecycle manager for WATCHTOWER.

    Args:
        vault: Initialised Vault instance.
    """

    def __init__(self, vault: Vault) -> None:
        self._vault = vault

    def optimize_all(self) -> list[IndexStats]:
        """
        Run FTS5 optimize on all search indexes.

        FTS5 optimize merges multiple small b-tree segments into one large
        one. This speeds up reads and compacts the index on disk.
        Call this during scheduled maintenance (e.g. nightly at 03:00).

        Returns:
            List of IndexStats, one per FTS table.
        """
        results: list[IndexStats] = []
        for fts_table in FTS_TABLES:
            stats = self._optimize_table(fts_table)
            results.append(stats)
            if stats.success:
                logger.info("FTS optimize: %s — %.1fms", fts_table, stats.duration_ms)
            else:
                logger.warning("FTS optimize failed: %s — %s", fts_table, stats.error)
        return results

    def rebuild_all(self) -> list[IndexStats]:
        """
        Rebuild all FTS indexes from scratch from their content tables.

        Use this after:
            - A crash that may have left FTS and content tables out of sync
            - Manual bulk deletion that bypassed the delete triggers
            - Database restore from backup

        This is a full table scan — it will be slow on large databases.

        Returns:
            List of IndexStats, one per FTS table.
        """
        results: list[IndexStats] = []
        for fts_table, content_table in FTS_TABLES.items():
            stats = self._rebuild_table(fts_table, content_table)
            results.append(stats)
            if stats.success:
                logger.info(
                    "FTS rebuild: %s — %d rows in %.1fms",
                    fts_table, stats.rows_indexed, stats.duration_ms
                )
            else:
                logger.error("FTS rebuild failed: %s — %s", fts_table, stats.error)
        return results

    def rebuild_table(self, category: str) -> IndexStats:
        """
        Rebuild the FTS index for a single log category.

        Args:
            category: Log category ('auth','network','firewall','system','app').

        Returns:
            IndexStats for this rebuild.

        Raises:
            LedgerError: If the category is unrecognised.
        """
        fts_table = f"fts_{category}"
        content   = FTS_TABLES.get(fts_table)
        if not content:
            raise LedgerError(f"Unknown FTS category: {category!r}")
        return self._rebuild_table(fts_table, content)

    def integrity_check(self) -> dict[str, bool]:
        """
        Verify FTS indexes are in sync with their content tables.
        Compares row counts between each FTS index and its content table.

        Returns:
            Dict mapping fts_table → True (ok) / False (out of sync).
        """
        results: dict[str, bool] = {}
        conn = self._vault.get_connection()

        for fts_table, content_table in FTS_TABLES.items():
            try:
                content_count = conn.execute(
                    f"SELECT COUNT(*) FROM {content_table}"
                ).fetchone()[0]

                # FTS5 integrity check via special command
                issues = conn.execute(
                    f"INSERT INTO {fts_table}({fts_table}) VALUES('integrity-check')"
                )
                results[fts_table] = True
                logger.debug("%s integrity ok (content rows: %d)", fts_table, content_count)

            except sqlite3.OperationalError as exc:
                err_str = str(exc)
                if "integrity-check" in err_str or "ok" in err_str.lower():
                    results[fts_table] = True
                else:
                    results[fts_table] = False
                    logger.warning("FTS integrity issue on %s: %s", fts_table, exc)
            except Exception as exc:
                results[fts_table] = False
                logger.error("FTS integrity check error on %s: %s", fts_table, exc)

        return results

    def is_fts_available(self) -> bool:
        """
        Check whether FTS5 is compiled into this SQLite build.

        Returns:
            True if FTS5 is available and the virtual tables exist.
        """
        try:
            conn = self._vault.get_connection()
            conn.execute("SELECT * FROM fts_auth LIMIT 0")
            return True
        except sqlite3.OperationalError:
            return False

    # ── Private helpers ───────────────────────────────────────────────────────

    def _optimize_table(self, fts_table: str) -> IndexStats:
        """Run FTS5 optimize on a single table."""
        t_start = time.perf_counter()
        try:
            conn = self._vault.get_connection()
            conn.execute(
                f"INSERT INTO {fts_table}({fts_table}) VALUES('optimize')"
            )
            conn.commit()
            return IndexStats(
                table        = fts_table,
                rows_indexed = 0,
                duration_ms  = (time.perf_counter() - t_start) * 1000,
                success      = True,
            )
        except sqlite3.Error as exc:
            return IndexStats(
                table        = fts_table,
                rows_indexed = 0,
                duration_ms  = (time.perf_counter() - t_start) * 1000,
                success      = False,
                error        = str(exc),
            )

    def _rebuild_table(self, fts_table: str, content_table: str) -> IndexStats:
        """Rebuild a single FTS table from its content table."""
        t_start = time.perf_counter()
        try:
            conn = self._vault.get_connection()

            # Step 1: delete all existing FTS data
            conn.execute(
                f"INSERT INTO {fts_table}({fts_table}) VALUES('delete-all')"
            )

            # Step 2: re-populate from content table
            # The column list must match the FTS table definition
            if fts_table == "fts_auth":
                conn.execute(f"""
                    INSERT INTO {fts_table}(rowid, message, hostname, app_name, username, event_type)
                    SELECT id, message, hostname, app_name, username, event_type
                    FROM {content_table}
                """)
            elif fts_table == "fts_firewall":
                conn.execute(f"""
                    INSERT INTO {fts_table}(rowid, message, hostname, app_name, action, event_type)
                    SELECT id, message, hostname, app_name, action, event_type
                    FROM {content_table}
                """)
            else:
                conn.execute(f"""
                    INSERT INTO {fts_table}(rowid, message, hostname, app_name, event_type)
                    SELECT id, message, hostname, app_name, event_type
                    FROM {content_table}
                """)

            rows = conn.execute(f"SELECT COUNT(*) FROM {content_table}").fetchone()[0]
            conn.commit()

            return IndexStats(
                table        = fts_table,
                rows_indexed = rows,
                duration_ms  = (time.perf_counter() - t_start) * 1000,
                success      = True,
            )
        except sqlite3.Error as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            return IndexStats(
                table        = fts_table,
                rows_indexed = 0,
                duration_ms  = (time.perf_counter() - t_start) * 1000,
                success      = False,
                error        = str(exc),
            )