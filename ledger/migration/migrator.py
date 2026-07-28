"""
ledger/migration/migrator.py
============================
WATCHTOWER — Database Migration Manager

Applies SQL migration scripts in version order.
Tracks which migrations have been applied in the schema_versions table.
Safe to run on every startup — already-applied migrations are skipped.

Design:
    Every .sql file in this directory is a migration.
    Files are named NNN_description.sql (e.g. 001_initial.sql).
    Migrations are applied in ascending order of NNN.
    Once applied, a migration is never re-applied.
    A failed migration raises MigrationError and halts startup.
"""

from __future__ import annotations

import logging
import re
import sqlite3
from pathlib import Path

from nucleus.exceptions import MigrationError

logger = logging.getLogger(__name__)

# Path to the directory containing this file
MIGRATION_DIR = Path(__file__).parent

# Regex to extract version number from filename: 001_name.sql → 1
_VERSION_RE = re.compile(r'^(\d+)_.+\.sql$')


def _get_migration_files() -> list[tuple[int, Path]]:
    """
    Discover and sort all .sql migration files in this directory.

    Returns:
        List of (version_number, path) tuples, sorted by version ascending.
    """
    files: list[tuple[int, Path]] = []
    for f in MIGRATION_DIR.glob("*.sql"):
        match = _VERSION_RE.match(f.name)
        if match:
            version = int(match.group(1))
            files.append((version, f))
    return sorted(files, key=lambda x: x[0])


def _ensure_version_table(conn: sqlite3.Connection) -> None:
    """
    Create the schema_versions tracking table if it does not exist.
    This table must exist before any other migration runs.

    Args:
        conn: Active SQLite connection.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_versions (
            version     INTEGER PRIMARY KEY,
            filename    TEXT    NOT NULL,
            applied_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
            checksum    TEXT    NOT NULL DEFAULT ''
        )
    """)
    conn.commit()


def _applied_versions(conn: sqlite3.Connection) -> set[int]:
    """
    Return the set of migration version numbers already applied.

    Args:
        conn: Active SQLite connection.

    Returns:
        Set of integer version numbers that have been applied.
    """
    rows = conn.execute("SELECT version FROM schema_versions").fetchall()
    return {row[0] for row in rows}


def _apply_migration(conn: sqlite3.Connection, version: int, path: Path) -> None:
    """
    Apply a single migration file inside a transaction.
    Marks it as applied in schema_versions on success.
    Rolls back and raises MigrationError on failure.

    Args:
        conn:    Active SQLite connection.
        version: Integer version number of this migration.
        path:    Path to the .sql file.

    Raises:
        MigrationError: If the SQL execution fails.
    """
    sql = path.read_text(encoding="utf-8")
    logger.info("Applying migration %03d: %s", version, path.name)

    try:
        # Execute migration SQL (may contain multiple statements)
        conn.executescript(sql)

        # Record successful application
        conn.execute(
            "INSERT INTO schema_versions (version, filename) VALUES (?, ?)",
            (version, path.name)
        )
        conn.commit()
        logger.info("Migration %03d applied successfully", version)

    except sqlite3.Error as exc:
        conn.rollback()
        raise MigrationError(
            migration_file=path.name,
            reason=str(exc)
        ) from exc


def run_migrations(db_path: str | Path) -> int:
    """
    Run all pending migrations against the database at db_path.

    Called once at WATCHTOWER startup by vault.py before accepting
    any log records. Safe to call repeatedly — skips already-applied
    migrations.

    Args:
        db_path: Filesystem path to the SQLite database file.

    Returns:
        Number of migrations applied in this run (0 if already up-to-date).

    Raises:
        MigrationError: If any migration fails to apply.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    try:
        _ensure_version_table(conn)
        applied  = _applied_versions(conn)
        pending  = [
            (v, p) for v, p in _get_migration_files()
            if v not in applied
        ]

        if not pending:
            logger.debug("Database schema is up-to-date (no pending migrations)")
            return 0

        logger.info(
            "Found %d pending migration(s): %s",
            len(pending),
            [p.name for _, p in pending]
        )

        for version, path in pending:
            _apply_migration(conn, version, path)

        logger.info("All migrations applied. Schema version: %d", pending[-1][0])
        return len(pending)

    finally:
        conn.close()


def current_version(db_path: str | Path) -> int:
    """
    Return the highest migration version currently applied.

    Args:
        db_path: Filesystem path to the SQLite database file.

    Returns:
        Highest applied version number, or 0 if no migrations applied.
    """
    db_path = Path(db_path)
    if not db_path.exists():
        return 0
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        _ensure_version_table(conn)
        row = conn.execute(
            "SELECT MAX(version) FROM schema_versions"
        ).fetchone()
        conn.close()
        return row[0] or 0
    except sqlite3.Error:
        return 0