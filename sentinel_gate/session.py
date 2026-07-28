"""
sentinel_gate/session.py
========================
WATCHTOWER — Session Lifecycle Manager

Creates, validates, and invalidates admin sessions.
Sessions are stored in the SQLite sessions table (ledger/001_initial.sql).
A session token is a 32-byte cryptographically random hex string.

Session lifecycle:
    1. Admin submits correct password → create_session() → token returned
    2. Browser stores token in an HttpOnly, Secure cookie
    3. Every portal request → validate_session() → returns session dict
    4. Admin clicks logout → invalidate_session() → token marked invalid
    5. Expired sessions → cleanup_expired() → removed by scheduler

Security properties:
    - Tokens are 256-bit random — not guessable
    - Stored as-is in cookie, SHA-256 hash stored in DB (breach-safe)
    - HttpOnly + Secure + SameSite=Strict cookie flags
    - IP binding: optional — warn if session IP changes
    - Absolute expiry: 8 hours (configurable)
    - Idle expiry: 30 minutes inactivity (configurable)
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import datetime
import threading
from typing import Optional

from nucleus.exceptions import SessionExpired, SessionInvalid, AuthError
from nucleus.telemetry  import metrics

logger = logging.getLogger(__name__)

# Token format: 64 hex chars = 32 bytes = 256 bits
_TOKEN_BYTES    = 32
_IDLE_TIMEOUT   = 1800      # 30 minutes idle → session invalid
_CLEANUP_EVERY  = 300       # run cleanup every 5 minutes


class SessionManager:
    """
    Manages admin sessions backed by SQLite sessions table.

    Args:
        db_path:          Path to the SQLite database file.
        lifetime_seconds: Absolute session lifetime in seconds (default 8h).
        idle_timeout:     Seconds of inactivity before expiry (default 30m).
    """

    def __init__(
        self,
        db_path: str,
        lifetime_seconds: int = 28800,
        idle_timeout: int     = _IDLE_TIMEOUT,
    ) -> None:
        self._db_path        = db_path
        self._lifetime       = lifetime_seconds
        self._idle_timeout   = idle_timeout
        self._last_cleanup   = 0.0
        self._lock           = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────

    def create_session(
        self,
        username: str   = "admin",
        role: str       = "admin",
        ip_address: str = "",
        user_agent: str = "",
    ) -> str:
        """
        Create a new authenticated session and return the session token.

        The raw token is returned to the caller (placed in cookie).
        Only the SHA-256 hash is stored in the database.

        Args:
            username:   Authenticated username.
            role:       Role assigned to this session.
            ip_address: Client IP for audit purposes.
            user_agent: Client user-agent string.

        Returns:
            Raw session token string (64 hex chars).
        """
        raw_token   = os.urandom(_TOKEN_BYTES).hex()
        token_hash  = self._hash_token(raw_token)
        now         = datetime.datetime.utcnow()
        expires_at  = now + datetime.timedelta(seconds=self._lifetime)

        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO sessions
                    (session_token, username, role, created_at,
                     last_active, expires_at, ip_address, user_agent, valid)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                token_hash,
                username,
                role,
                now.strftime("%Y-%m-%d %H:%M:%S"),
                now.strftime("%Y-%m-%d %H:%M:%S"),
                expires_at.strftime("%Y-%m-%d %H:%M:%S"),
                ip_address,
                user_agent[:512] if user_agent else "",
            ))
            conn.commit()
            metrics.portal_active_sessions.increment()
            logger.info(
                "Session created for %s from %s (expires %s)",
                username, ip_address, expires_at.strftime("%Y-%m-%d %H:%M:%S")
            )
        finally:
            conn.close()

        self._maybe_cleanup()
        return raw_token

    def validate_session(
        self,
        raw_token: str,
        ip_address: str = "",
    ) -> dict:
        """
        Validate a session token from a browser cookie.

        Updates last_active timestamp on successful validation.

        Args:
            raw_token:  Raw token from the browser cookie.
            ip_address: Current request IP (for audit logging).

        Returns:
            Session dict with username, role, created_at, ip_address.

        Raises:
            SessionInvalid: Token not found or already invalidated.
            SessionExpired: Token exists but has expired.
        """
        if not raw_token or len(raw_token) != _TOKEN_BYTES * 2:
            raise SessionInvalid("Malformed session token")

        token_hash = self._hash_token(raw_token)
        conn       = self._connect()

        try:
            row = conn.execute("""
                SELECT id, username, role, created_at, last_active,
                       expires_at, ip_address, valid
                FROM sessions
                WHERE session_token = ? AND valid = 1
                LIMIT 1
            """, (token_hash,)).fetchone()

            if not row:
                raise SessionInvalid("Session not found or invalidated")

            row = dict(row)
            now = datetime.datetime.utcnow()

            # Check absolute expiry
            expires = datetime.datetime.strptime(
                row["expires_at"], "%Y-%m-%d %H:%M:%S"
            )
            if now > expires:
                self._invalidate_by_hash(conn, token_hash)
                conn.commit()
                raise SessionExpired("Session has expired — please log in again")

            # Check idle timeout
            last_active = datetime.datetime.strptime(
                row["last_active"], "%Y-%m-%d %H:%M:%S"
            )
            if (now - last_active).total_seconds() > self._idle_timeout:
                self._invalidate_by_hash(conn, token_hash)
                conn.commit()
                raise SessionExpired(
                    "Session expired due to inactivity — please log in again"
                )

            # Warn on IP change (not enforced — some users have dynamic IPs)
            if ip_address and row["ip_address"] and ip_address != row["ip_address"]:
                logger.warning(
                    "Session IP changed for %s: was %s, now %s",
                    row["username"], row["ip_address"], ip_address
                )

            # Touch last_active
            conn.execute("""
                UPDATE sessions
                SET last_active = ?
                WHERE session_token = ?
            """, (now.strftime("%Y-%m-%d %H:%M:%S"), token_hash))
            conn.commit()

            return {
                "username":   row["username"],
                "role":       row["role"],
                "created_at": row["created_at"],
                "ip_address": row["ip_address"],
                "session_id": token_hash[:16],   # prefix only for logging
            }

        finally:
            conn.close()

    def invalidate_session(self, raw_token: str) -> None:
        """
        Invalidate a session (logout).

        Args:
            raw_token: Raw token from the browser cookie.
        """
        if not raw_token:
            return
        token_hash = self._hash_token(raw_token)
        conn       = self._connect()
        try:
            self._invalidate_by_hash(conn, token_hash)
            conn.commit()
            metrics.portal_active_sessions.decrement()
            logger.info("Session invalidated: %s...", token_hash[:16])
        finally:
            conn.close()

    def invalidate_all(self, username: str = "admin") -> int:
        """
        Invalidate all sessions for a given user.
        Used when password is changed.

        Args:
            username: Username whose sessions to invalidate.

        Returns:
            Number of sessions invalidated.
        """
        conn = self._connect()
        try:
            cur = conn.execute("""
                UPDATE sessions SET valid = 0
                WHERE username = ? AND valid = 1
            """, (username,))
            conn.commit()
            count = cur.rowcount
            logger.info("Invalidated %d session(s) for %s", count, username)
            return count
        finally:
            conn.close()

    def cleanup_expired(self) -> int:
        """
        Delete expired and invalidated sessions from the database.
        Called by the scheduler daily.

        Returns:
            Number of sessions deleted.
        """
        conn = self._connect()
        try:
            # Delete sessions expired more than 24 hours ago
            cutoff = (
                datetime.datetime.utcnow() - datetime.timedelta(hours=24)
            ).strftime("%Y-%m-%d %H:%M:%S")

            cur = conn.execute("""
                DELETE FROM sessions
                WHERE valid = 0
                   OR expires_at < ?
            """, (cutoff,))
            conn.commit()
            deleted = cur.rowcount
            if deleted:
                logger.info("Session cleanup: deleted %d expired sessions", deleted)
            return deleted
        finally:
            conn.close()

    def active_sessions(self) -> list[dict]:
        """
        Return all currently valid, non-expired sessions.
        Used by the sessions.html admin page.

        Returns:
            List of session dicts (token hash prefix, username, IP, dates).
        """
        conn = self._connect()
        try:
            now  = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            rows = conn.execute("""
                SELECT
                    substr(session_token, 1, 16) AS token_prefix,
                    username, role, created_at, last_active,
                    expires_at, ip_address, user_agent
                FROM sessions
                WHERE valid = 1 AND expires_at > ?
                ORDER BY last_active DESC
            """, (now,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _hash_token(raw_token: str) -> str:
        """SHA-256 hash of the raw token for safe DB storage."""
        return hashlib.sha256(raw_token.encode()).hexdigest()

    def _invalidate_by_hash(self, conn: sqlite3.Connection, token_hash: str) -> None:
        conn.execute(
            "UPDATE sessions SET valid = 0 WHERE session_token = ?",
            (token_hash,)
        )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _maybe_cleanup(self) -> None:
        """Run cleanup if enough time has passed since last run."""
        import time
        now = time.time()
        with self._lock:
            if now - self._last_cleanup > _CLEANUP_EVERY:
                self._last_cleanup = now
                try:
                    self.cleanup_expired()
                except Exception as exc:
                    logger.debug("Session cleanup error: %s", exc)