"""
portal/runtime.py
==================
WATCHTOWER — Portal runtime wiring.

The auth/audit classes (Vault, Scribe, Archivist, Auditor, Trail,
SessionManager, LockoutManager, APIKeyManager) are each independently
correct, but nothing previously constructed and connected them for the
portal to use. This module builds one shared set of instances, backed
by the same ledger database as the syslog ingest side, and is imported
by portal/views.py and portal/middleware.py instead of talking to the
raw classes directly.

A tiny `Principal` stands in for "the logged-in admin" so login_required
/ role_required (which expect an object with .username / .role) have
something to check.
"""

from __future__ import annotations

from dataclasses import dataclass

from nucleus.config import cfg

from ledger.vault import Vault
from ledger.scribe import Scribe
from ledger.archivist import Archivist

from chronicle.auditor import Auditor
from chronicle.trail import Trail

from sentinel_gate.session import SessionManager
from sentinel_gate.lockout import LockoutManager
from sentinel_gate.apikey import APIKeyManager


@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    id: str = ""

    def __post_init__(self):
        if not self.id:
            object.__setattr__(self, "id", self.username)


vault = Vault(cfg.ledger.db_path)
vault.initialise()

scribe = Scribe(vault)
archivist = Archivist(vault)

auditor = Auditor(scribe)
trail = Trail(archivist)

sessions = SessionManager(cfg.ledger.db_path, lifetime_seconds=cfg.auth.session_lifetime)
lockout = LockoutManager(
    max_failures=cfg.auth.max_failed_logins,
    lockout_seconds=cfg.auth.lockout_duration,
)
apikeys = APIKeyManager(cfg.ledger.db_path)

__all__ = ["Principal", "vault", "scribe", "archivist", "auditor", "trail",
           "sessions", "lockout", "apikeys"]
