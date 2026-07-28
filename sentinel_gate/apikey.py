"""
sentinel_gate/apikey.py
=======================
WATCHTOWER — API Key Management

Provides programmatic access to WATCHTOWER's REST API without
requiring browser-based session authentication.

API key format:
    wtk_<32_random_hex_chars>
    Example: wtk_a3f8e2d91c7b4056a8e31df720c69b4e

Storage:
    Only the SHA-256 hash of the key is stored in the database.
    The raw key is shown once at creation and never again.
    If lost, the admin must generate a new key.

Security:
    - Keys are 256-bit random — unguessable
    - Only the hash is stored (breach-safe)
    - Keys have configurable expiry dates
    - Keys carry a role (viewer/analyst/admin)
    - Every API call updates last_used timestamp
    - Keys can be revoked instantly

Usage in requests:
    Authorization: Bearer wtk_a3f8e2d91c7b4056a8e31df720c69b4e
    or
    X-API-Key: wtk_a3f8e2d91c7b4056a8e31df720c69b4e
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import datetime
from typing import Optional

from nucleus.exceptions import APIKeyInvalid, AuthError
from nucleus.constants import Role

logger = logging.getLogger(__name__)

_KEY_PREFIX = "wtk_"
_KEY_BYTES  = 32


class APIKeyManager:
    """
    API key lifecycle manager backed by SQLite api_keys table.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path

    def create_key(
        self,
        name:       str,
        role:       str = Role.VIEWER,
        notes:      str = "",
        expires_in_days: Optional[int] = None,
    ) -> tuple[str, dict]:
        """
        Generate a new API key and store its hash in the database.

        Args:
            name:            Human-readable name for this key.
            role:            Role assigned to requests using this key.
            notes:           Optional notes (purpose, owner).
            expires_in_days: Days until expiry, or None for no expiry.

        Returns:
            Tuple of (raw_key_string, key_record_dict).
            The raw_key_string is shown once — store it securely.

        Raises:
            AuthError: If a key with this name already exists.
        """
        raw_key    = _KEY_PREFIX + os.urandom(_KEY_BYTES).hex()
        key_hash   = self._hash_key(raw_key)
        key_prefix = raw_key[:12]   # "wtk_" + first 8 chars for display

        now        = datetime.datetime.utcnow()
        expires_at = None
        if expires_in_days:
            expires_at = (now + datetime.timedelta(days=expires_in_days)
                         ).strftime("%Y-%m-%d %H:%M:%S")

        conn = self._connect()
        try:
            conn.execute("""
                INSERT INTO api_keys
                    (name, key_hash, key_prefix, role,
                     created_at, expires_at, active, notes)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """, (
                name,
                key_hash,
                key_prefix,
                role,
                now.strftime("%Y-%m-%d %H:%M:%S"),
                expires_at,
                notes,
            ))
            conn.commit()

            record = {
                "name":       name,
                "key_prefix": key_prefix,
                "role":       role,
                "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                "expires_at": expires_at,
                "notes":      notes,
            }
            logger.info(
                "API key created: name=%s role=%s prefix=%s",
                name, role, key_prefix
            )
            return raw_key, record

        except sqlite3.IntegrityError:
            raise AuthError(f"API key name '{name}' already exists")
        finally:
            conn.close()

    def validate_key(self, raw_key: str) -> dict:
        """
        Validate an API key from a request header.

        Updates last_used timestamp on success.

        Args:
            raw_key: Raw key string from the Authorization header.

        Returns:
            Dict with role, name, key_prefix for the request context.

        Raises:
            APIKeyInvalid: If the key does not exist, is revoked, or expired.
        """
        if not raw_key or not raw_key.startswith(_KEY_PREFIX):
            raise APIKeyInvalid("Invalid API key format")

        key_hash = self._hash_key(raw_key.strip())
        conn     = self._connect()

        try:
            row = conn.execute("""
                SELECT id, name, key_prefix, role,
                       created_at, expires_at, active
                FROM api_keys
                WHERE key_hash = ? AND active = 1
                LIMIT 1
            """, (key_hash,)).fetchone()

            if not row:
                raise APIKeyInvalid("API key not found or revoked")

            row = dict(row)

            # Check expiry
            if row["expires_at"]:
                expiry = datetime.datetime.strptime(
                    row["expires_at"], "%Y-%m-%d %H:%M:%S"
                )
                if datetime.datetime.utcnow() > expiry:
                    raise APIKeyInvalid("API key has expired")

            # Touch last_used
            conn.execute("""
                UPDATE api_keys
                SET last_used = ?
                WHERE id = ?
            """, (
                datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                row["id"]
            ))
            conn.commit()

            return {
                "name":       row["name"],
                "role":       row["role"],
                "key_prefix": row["key_prefix"],
            }

        finally:
            conn.close()

    def revoke_key(self, name: str) -> bool:
        """
        Revoke an API key by name (sets active=0).

        Args:
            name: Name of the key to revoke.

        Returns:
            True if the key was found and revoked, False if not found.
        """
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE api_keys SET active = 0 WHERE name = ? AND active = 1",
                (name,)
            )
            conn.commit()
            if cur.rowcount:
                logger.info("API key revoked: %s", name)
                return True
            return False
        finally:
            conn.close()

    def list_keys(self) -> list[dict]:
        """
        List all API keys (hashes NOT included).

        Returns:
            List of key record dicts (safe to send to the admin UI).
        """
        conn = self._connect()
        try:
            rows = conn.execute("""
                SELECT name, key_prefix, role, created_at,
                       last_used, expires_at, active, notes
                FROM api_keys
                ORDER BY created_at DESC
            """).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def delete_key(self, name: str) -> bool:
        """
        Permanently delete an API key record.

        Args:
            name: Key name to delete.

        Returns:
            True if deleted.
        """
        conn = self._connect()
        try:
            cur = conn.execute(
                "DELETE FROM api_keys WHERE name = ?", (name,)
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn