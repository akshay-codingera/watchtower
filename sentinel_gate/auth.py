"""
sentinel_gate/auth.py
=====================
WATCHTOWER — Credential Verification

Handles password hashing and verification for the single admin account.
Uses PBKDF2-HMAC-SHA256 with a random salt — far stronger than plain SHA256.

Design:
    WATCHTOWER has one admin account. The password hash is stored in
    config.ini as admin_password_hash. No user table is needed.

    Hash format stored in config.ini:
        pbkdf2:sha256:600000:<hex_salt>:<hex_hash>

    The setup utility (or first-run wizard) calls hash_password() to
    generate this string, which the admin then places in config.ini.

    For backward compatibility we also accept a plain SHA-256 hex string
    (32 bytes = 64 hex chars) — used in the development config template.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import logging

from nucleus.exceptions import InvalidCredentials, AuthError

logger = logging.getLogger(__name__)

# PBKDF2 parameters
_ALGORITHM  = "sha256"
_ITERATIONS = 600_000          # OWASP 2023 recommendation for PBKDF2-SHA256
_SALT_BYTES = 32
_HASH_BYTES = 32
_PREFIX     = "pbkdf2"


def hash_password(plain: str) -> str:
    """
    Hash a plaintext password using PBKDF2-HMAC-SHA256.

    Returns a self-describing string suitable for storage in config.ini:
        pbkdf2:sha256:600000:<hex_salt>:<hex_hash>

    Args:
        plain: The plaintext password chosen by the admin.

    Returns:
        Encoded hash string.
    """
    salt     = os.urandom(_SALT_BYTES)
    dk       = hashlib.pbkdf2_hmac(
        _ALGORITHM, plain.encode("utf-8"), salt, _ITERATIONS, _HASH_BYTES
    )
    return f"{_PREFIX}:{_ALGORITHM}:{_ITERATIONS}:{salt.hex()}:{dk.hex()}"


def verify_password(plain: str, stored_hash: str) -> bool:
    """
    Verify a plaintext password against a stored hash string.

    Supports two formats:
        1. pbkdf2:sha256:<iter>:<salt_hex>:<hash_hex>  (preferred)
        2. <64-char hex string>  (plain SHA-256 legacy / dev config)

    Args:
        plain:       The plaintext password to verify.
        stored_hash: The hash string from config.ini.

    Returns:
        True if the password matches.

    Raises:
        InvalidCredentials: If the password does not match.
        AuthError:          If the stored hash is malformed.
    """
    stored_hash = stored_hash.strip()

    if stored_hash.startswith(_PREFIX + ":"):
        matched = _verify_pbkdf2(plain, stored_hash)
    elif len(stored_hash) == 64 and _is_hex(stored_hash):
        # Legacy SHA-256 (dev config only — not suitable for production)
        matched = _verify_sha256(plain, stored_hash)
    else:
        raise AuthError(
            "admin_password_hash in config.ini is malformed. "
            "Run: python -m sentinel_gate.auth to generate a new hash."
        )

    if not matched:
        raise InvalidCredentials("Password does not match")

    return True


def generate_hash_for_config(plain: str) -> str:
    """
    Convenience function for the setup wizard / CLI.
    Prints the hash string that should go into config.ini.

    Args:
        plain: Chosen admin password.

    Returns:
        Hash string ready for config.ini.
    """
    return hash_password(plain)


# ── Private helpers ───────────────────────────────────────────────────────────

def _verify_pbkdf2(plain: str, stored: str) -> bool:
    """Verify against pbkdf2:sha256:<iter>:<salt>:<hash> format."""
    try:
        parts = stored.split(":")
        if len(parts) != 5 or parts[0] != _PREFIX:
            raise AuthError(f"Malformed PBKDF2 hash: expected 5 parts, got {len(parts)}")

        _, algo, iterations_str, salt_hex, hash_hex = parts
        iterations = int(iterations_str)
        salt       = bytes.fromhex(salt_hex)
        expected   = bytes.fromhex(hash_hex)

        computed = hashlib.pbkdf2_hmac(
            algo, plain.encode("utf-8"), salt, iterations, len(expected)
        )
        # Constant-time comparison prevents timing attacks
        return hmac.compare_digest(computed, expected)

    except (ValueError, KeyError) as exc:
        raise AuthError(f"Cannot verify PBKDF2 hash: {exc}") from exc


def _verify_sha256(plain: str, stored_hex: str) -> bool:
    """Verify against plain SHA-256 hex (dev / legacy only)."""
    computed = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed, stored_hex)


def _is_hex(s: str) -> bool:
    """Return True if string contains only hex characters."""
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


# ── CLI helper ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import getpass
    print("WATCHTOWER — Password Hash Generator")
    print("=" * 40)
    pw = getpass.getpass("Enter new admin password: ")
    if len(pw) < 8:
        print("ERROR: Password must be at least 8 characters.")
    else:
        h = hash_password(pw)
        print(f"\nAdd this to config.ini under [auth]:")
        print(f"admin_password_hash = {h}")