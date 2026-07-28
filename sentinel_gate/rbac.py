"""
sentinel_gate/rbac.py
=====================
WATCHTOWER — Role-Based Access Control

Defines roles, permissions, and enforcement decorators for the portal.

Roles (from nucleus/constants.py):
    admin    — full access: view, configure, delete, export, manage alerts
    analyst  — view logs, acknowledge alerts, run searches, export
    viewer   — read-only: view logs and devices, no export, no config
    auditor  — audit trail and compliance only, no log content

Permission matrix:
    Permission              admin   analyst  viewer  auditor
    ─────────────────────── ─────── ──────── ─────── ───────
    view_logs               ✓       ✓        ✓       ✗
    view_devices            ✓       ✓        ✓       ✗
    view_alerts             ✓       ✓        ✓       ✗
    view_analytics          ✓       ✓        ✓       ✗
    acknowledge_alert       ✓       ✓        ✗       ✗
    export_logs             ✓       ✓        ✗       ✗
    manage_alerts           ✓       ✗        ✗       ✗
    manage_devices          ✓       ✗        ✗       ✗
    view_audit_trail        ✓       ✗        ✗       ✓
    view_sessions           ✓       ✗        ✗       ✓
    change_settings         ✓       ✗        ✗       ✗
    manage_api_keys         ✓       ✗        ✗       ✗
    view_health             ✓       ✓        ✓       ✓
"""

from __future__ import annotations

import functools
import logging
from typing import Callable

from nucleus.constants import Role
from nucleus.exceptions import PermissionDenied, SessionInvalid

logger = logging.getLogger(__name__)


class Permission:
    """All permission constants used across the portal."""
    VIEW_LOGS         = "view_logs"
    VIEW_DEVICES      = "view_devices"
    VIEW_ALERTS       = "view_alerts"
    VIEW_ANALYTICS    = "view_analytics"
    ACKNOWLEDGE_ALERT = "acknowledge_alert"
    EXPORT_LOGS       = "export_logs"
    MANAGE_ALERTS     = "manage_alerts"
    MANAGE_DEVICES    = "manage_devices"
    VIEW_AUDIT        = "view_audit_trail"
    VIEW_SESSIONS     = "view_sessions"
    CHANGE_SETTINGS   = "change_settings"
    MANAGE_API_KEYS   = "manage_api_keys"
    VIEW_HEALTH       = "view_health"


# ── Role → set of permissions ──────────────────────────────────────────────────

_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {

    Role.ADMIN: frozenset({
        Permission.VIEW_LOGS,
        Permission.VIEW_DEVICES,
        Permission.VIEW_ALERTS,
        Permission.VIEW_ANALYTICS,
        Permission.ACKNOWLEDGE_ALERT,
        Permission.EXPORT_LOGS,
        Permission.MANAGE_ALERTS,
        Permission.MANAGE_DEVICES,
        Permission.VIEW_AUDIT,
        Permission.VIEW_SESSIONS,
        Permission.CHANGE_SETTINGS,
        Permission.MANAGE_API_KEYS,
        Permission.VIEW_HEALTH,
    }),

    Role.ANALYST: frozenset({
        Permission.VIEW_LOGS,
        Permission.VIEW_DEVICES,
        Permission.VIEW_ALERTS,
        Permission.VIEW_ANALYTICS,
        Permission.ACKNOWLEDGE_ALERT,
        Permission.EXPORT_LOGS,
        Permission.VIEW_HEALTH,
    }),

    Role.VIEWER: frozenset({
        Permission.VIEW_LOGS,
        Permission.VIEW_DEVICES,
        Permission.VIEW_ALERTS,
        Permission.VIEW_ANALYTICS,
        Permission.VIEW_HEALTH,
    }),

    Role.AUDITOR: frozenset({
        Permission.VIEW_AUDIT,
        Permission.VIEW_SESSIONS,
        Permission.VIEW_HEALTH,
    }),
}


# ── RBAC enforcement functions ────────────────────────────────────────────────

def has_permission(role: str, permission: str) -> bool:
    """
    Check whether a role has a specific permission.

    Args:
        role:       Role string (admin/analyst/viewer/auditor).
        permission: Permission constant from Permission class.

    Returns:
        True if the role holds the permission.
    """
    perms = _ROLE_PERMISSIONS.get(role, frozenset())
    return permission in perms


def check_permission(role: str, permission: str) -> None:
    """
    Assert that a role has a permission — raise PermissionDenied if not.

    Args:
        role:       Role string of the current session.
        permission: Required permission constant.

    Raises:
        PermissionDenied: If the role lacks the permission.
    """
    if not has_permission(role, permission):
        raise PermissionDenied(
            required_role=permission,
            actual_role=role,
        )


def get_permissions(role: str) -> list[str]:
    """
    Return all permissions held by a role.

    Args:
        role: Role string.

    Returns:
        Sorted list of permission strings.
    """
    return sorted(_ROLE_PERMISSIONS.get(role, frozenset()))


def role_hierarchy_gte(role: str, minimum_role: str) -> bool:
    """
    Return True if `role` is at or above `minimum_role` in hierarchy.

    Hierarchy: admin > analyst > viewer > auditor

    Args:
        role:         Role to check.
        minimum_role: Minimum required role.

    Returns:
        True if role meets or exceeds minimum_role.
    """
    _HIERARCHY = {
        Role.ADMIN:   4,
        Role.ANALYST: 3,
        Role.VIEWER:  2,
        Role.AUDITOR: 1,
    }
    return _HIERARCHY.get(role, 0) >= _HIERARCHY.get(minimum_role, 0)


# ── Flask decorator ───────────────────────────────────────────────────────────

def require_permission(permission: str):
    """
    Flask route decorator that enforces a permission check.

    Reads the current session role from Flask's session dict.
    Returns 403 JSON response if the check fails.

    Usage:
        @app.route('/api/logs/export')
        @login_required
        @require_permission(Permission.EXPORT_LOGS)
        def export_logs():
            ...
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                from flask import session, jsonify
                role = session.get("role", "")
                if not role:
                    return jsonify({"error": "Not authenticated"}), 401
                check_permission(role, permission)
                return f(*args, **kwargs)
            except PermissionDenied as exc:
                logger.warning(
                    "Permission denied: %s required '%s'", role, permission
                )
                try:
                    from flask import jsonify
                    return jsonify({"error": str(exc)}), 403
                except Exception:
                    return str(exc), 403
        return wrapper
    return decorator


def require_role(minimum_role: str):
    """
    Flask route decorator that enforces a minimum role level.

    Args:
        minimum_role: Minimum role required (admin/analyst/viewer/auditor).

    Usage:
        @app.route('/settings')
        @login_required
        @require_role(Role.ADMIN)
        def settings():
            ...
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                from flask import session, jsonify
                role = session.get("role", "")
                if not role:
                    return jsonify({"error": "Not authenticated"}), 401
                if not role_hierarchy_gte(role, minimum_role):
                    logger.warning(
                        "Role insufficient: user has '%s', needs '%s'",
                        role, minimum_role
                    )
                    return jsonify({
                        "error": f"Requires role '{minimum_role}' or above"
                    }), 403
                return f(*args, **kwargs)
            except Exception as exc:
                try:
                    from flask import jsonify
                    return jsonify({"error": str(exc)}), 403
                except Exception:
                    return str(exc), 403
        return wrapper
    return decorator