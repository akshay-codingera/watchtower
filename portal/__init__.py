"""Watchtower portal package.

The portal is a presentation-only layer built on Flask. It never contains
business logic, never touches SQLite directly, and never bypasses the
upstream modules (``nucleus``, ``ledger``, ``intake``, ``pipeline``,
``beacon``, ``sentinel_gate``, ``chronicle``, ``dispatch``).

Public entry point:
    from portal.gate import create_app
"""

from portal.gate import create_app

__all__ = ["create_app"]
