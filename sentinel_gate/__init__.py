"""
sentinel_gate/
==============
WATCHTOWER security and authentication layer.

Controls who enters the portal and what they can do.
Every request to the Flask portal passes through this layer.

Modules:
    auth.py     — password hashing and credential verification
    session.py  — session lifecycle: create, validate, invalidate
    rbac.py     — role definitions and permission enforcement
    apikey.py   — API key generation, hashing, validation
    lockout.py  — brute force detection and temporary lockout

Public interface:
    from sentinel_gate.auth    import verify_password, hash_password
    from sentinel_gate.session import SessionManager
    from sentinel_gate.rbac    import require_role, Permission
    from sentinel_gate.apikey  import APIKeyManager
    from sentinel_gate.lockout import LockoutManager
"""