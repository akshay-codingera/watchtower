"""
ledger/vault.py
===============
WATCHTOWER — Database Connection Manager

The vault is the single point of contact with SQLite.
Every other ledger module (scribe, archivist, indexer, retention)
receives a connection from the vault — they never open their own.

Responsibilities:
    - Database initialization (WAL mode, foreign keys, pragmas)
    - Thread-safe connection pool (one connection per thread)
    - Context manager for automatic commit / rollback
    - Schema migration on startup
    - Graceful shutdown with connection draining
    - Database health checks

Design note on thread-local connections:
    SQLite connections cannot be safely shared between threads.
    We use threading.local() so each thread gets its own connection.
    This is the correct pattern for multi-threaded SQLite usage.
    The writer thread, the Flask thread, and the scheduler thread
    each get their own connection opened on first use.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from nucleus.exceptions import DatabaseConnectionError, LedgerError
from ledger.migration.migrator import run_migrations, current_version

logger = logging.getLogger(__name__)

# ── Module-level thread-local connection storage ──────────────────────────────
_thread_local = threading.local()


class Vault:
    """
    Thread-safe SQLite connection manager for WATCHTOWER.

    Usage:
        vault = Vault("logs/syslog.db")
        vault.initialise()                     # call once at startup

        with vault.connection() as conn:       # auto-commit/rollback
            conn.execute("SELECT ...")

        conn = vault.get_connection()          # manual management
    """

    # SQLite pragmas applied to every new connection
    _PRAGMAS: list[str] = [
        "PRAGMA journal_mode=WAL",
        "PRAGMA foreign_keys=ON",
        "PRAGMA synchronous=NORMAL",     # WAL mode safe, faster than FULL
        "PRAGMA cache_size=-32000",      # 32 MB page cache per connection
        "PRAGMA temp_store=MEMORY",      # temp tables in RAM
        "PRAGMA mmap_size=268435456",    # 256 MB memory-mapped I/O
        "PRAGMA busy_timeout=5000",      # wait up to 5s on lock before error
    ]

    def __init__(self, db_path: str | Path):
        """
        Args:
            db_path: Filesystem path to the SQLite database file.
                     Parent directories are created if they do not exist.
        """
        self._db_path    = Path(db_path)
        self._initialised = False
        self._shutdown    = False
        self._init_lock   = threading.Lock()

    # ── Initialisation ────────────────────────────────────────────────────────

    def initialise(self) -> None:
        """
        Prepare the database for use.

        Creates the database file and parent directories if needed,
        applies all pending migrations, and verifies connectivity.

        Call once at application startup before any other ledger operation.

        Raises:
            DatabaseConnectionError: If the database cannot be opened.
            MigrationError: If a migration fails to apply.
        """
        with self._init_lock:
            if self._initialised:
                return

            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            logger.info("Initialising vault at %s", self._db_path)

            # Verify we can connect
            try:
                conn = self._open_connection()
                conn.execute("SELECT 1")
                conn.close()
            except sqlite3.Error as exc:
                raise DatabaseConnectionError(
                    f"Cannot open database at {self._db_path}: {exc}"
                ) from exc

            # Apply any pending migrations
            applied = run_migrations(self._db_path)
            if applied:
                logger.info("Applied %d migration(s)", applied)

            version = current_version(self._db_path)
            logger.info("Database schema version: %d", version)

            self._initialised = True
            logger.info("Vault ready")

    # ── Connection management ─────────────────────────────────────────────────

    def get_connection(self) -> sqlite3.Connection:
        """
        Return the connection for the current thread.
        Creates a new one if this thread has not connected yet.

        Returns:
            sqlite3.Connection with all pragmas applied.

        Raises:
            DatabaseConnectionError: If connection cannot be established.
            LedgerError: If vault has been shut down.
        """
        if self._shutdown:
            raise LedgerError("Vault has been shut down")

        if not self._initialised:
            raise LedgerError(
                "Vault.initialise() must be called before get_connection()"
            )

        conn = getattr(_thread_local, "connection", None)
        if conn is None:
            conn = self._open_connection()
            _thread_local.connection = conn
            logger.debug(
                "Opened new connection for thread %s",
                threading.current_thread().name
            )
        return conn

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Context manager that provides a connection with automatic
        commit on success and rollback on exception.

        Usage:
            with vault.connection() as conn:
                conn.execute("INSERT INTO ...")
                # commits here automatically

        Yields:
            sqlite3.Connection: Thread-local database connection.

        Raises:
            LedgerError: If the vault is not initialised or is shut down.
        """
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise LedgerError(f"Database operation failed: {exc}") from exc
        except Exception:
            conn.rollback()
            raise

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """
        Explicit transaction context manager.
        Use for batch operations where you want to commit only after
        all operations in the batch succeed.

        Usage:
            with vault.transaction() as conn:
                for record in batch:
                    conn.execute("INSERT ...", record)
                # all inserts committed together at end

        Yields:
            sqlite3.Connection ready for use within the transaction.
        """
        conn = self.get_connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ── Health and diagnostics ────────────────────────────────────────────────

    def ping(self) -> bool:
        """
        Verify the database is reachable and responding.

        Returns:
            True if healthy, False otherwise.
        """
        try:
            conn = self.get_connection()
            conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def stats(self) -> dict:
        """
        Return database statistics for the /health endpoint and dashboard.

        Returns:
            Dict with size_bytes, page_count, page_size, wal_frames,
            schema_version, and per-table row counts.
        """
        try:
            conn = self.get_connection()

            page_count = conn.execute("PRAGMA page_count").fetchone()[0]
            page_size  = conn.execute("PRAGMA page_size").fetchone()[0]
            wal_frames = conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()

            table_counts: dict[str, int] = {}
            for table in ["auth_logs", "network_logs", "firewall_logs",
                          "system_logs", "app_logs", "devices", "alert_history"]:
                try:
                    row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                    table_counts[table] = row[0] if row else 0
                except sqlite3.Error:
                    table_counts[table] = -1

            size_bytes = self._db_path.stat().st_size if self._db_path.exists() else 0

            return {
                "db_path":        str(self._db_path),
                "size_bytes":     size_bytes,
                "size_mb":        round(size_bytes / 1_048_576, 2),
                "page_count":     page_count,
                "page_size":      page_size,
                "wal_frames":     wal_frames[0] if wal_frames else 0,
                "schema_version": current_version(self._db_path),
                "table_counts":   table_counts,
                "total_logs":     sum(
                    v for k, v in table_counts.items()
                    if k.endswith("_logs") and v > 0
                ),
            }
        except Exception as exc:
            logger.error("Failed to collect vault stats: %s", exc)
            return {"error": str(exc)}

    def checkpoint(self) -> None:
        """
        Force a WAL checkpoint — flush WAL frames to the main database file.
        Call periodically to prevent the WAL file from growing unbounded.
        """
        try:
            conn = self.get_connection()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            logger.debug("WAL checkpoint completed")
        except sqlite3.Error as exc:
            logger.warning("WAL checkpoint failed: %s", exc)

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        """
        Close the current thread's connection and mark the vault as shut down.
        Call from the main thread on application exit.
        """
        self._shutdown = True
        conn = getattr(_thread_local, "connection", None)
        if conn:
            try:
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.close()
                _thread_local.connection = None
                logger.info("Vault connection closed gracefully")
            except sqlite3.Error as exc:
                logger.warning("Error during vault shutdown: %s", exc)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _open_connection(self) -> sqlite3.Connection:
        """
        Open a new SQLite connection and apply all pragmas.

        Returns:
            Configured sqlite3.Connection.

        Raises:
            DatabaseConnectionError: If the connection cannot be opened.
        """
        retries = 3
        for attempt in range(retries):
            try:
                conn = sqlite3.connect(
                    str(self._db_path),
                    check_same_thread=False,   # we manage thread safety ourselves
                    timeout=10.0,
                    isolation_level=None,      # autocommit off — we manage transactions
                )
                conn.row_factory = sqlite3.Row  # rows accessible by column name

                for pragma in self._PRAGMAS:
                    conn.execute(pragma)

                return conn

            except sqlite3.OperationalError as exc:
                if attempt < retries - 1:
                    logger.warning(
                        "Connection attempt %d failed: %s. Retrying...",
                        attempt + 1, exc
                    )
                    time.sleep(0.5 * (attempt + 1))
                else:
                    raise DatabaseConnectionError(
                        f"Failed to open {self._db_path} after {retries} attempts: {exc}"
                    ) from exc

        raise DatabaseConnectionError("Unreachable")  # pragma: no cover

    def __repr__(self) -> str:
        return (
            f"Vault(path={self._db_path!r}, "
            f"initialised={self._initialised}, "
            f"shutdown={self._shutdown})"
        )