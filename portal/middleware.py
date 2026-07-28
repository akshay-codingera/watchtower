"""Request-lifecycle middleware for the Watchtower portal.

Provides:
    * structured request/response access logging
    * session lookup delegated to ``sentinel_gate.session``
    * API key authentication delegated to ``sentinel_gate.apikey``
    * rate-limiting hook decorator
    * role/permission decorators (``login_required`` / ``role_required``)
"""

from __future__ import annotations

import functools
import logging
import time
import uuid
from collections import deque
from threading import Lock
from typing import Any, Callable, Deque, Final, Optional

from flask import Flask, abort, current_app, g, request, session

from nucleus.exceptions import AuthFailure  # type: ignore[import-not-found]
from sentinel_gate import apikey as _apikey  # type: ignore[import-not-found]
from sentinel_gate import rbac as _rbac  # type: ignore[import-not-found]
from sentinel_gate import session as _session  # type: ignore[import-not-found]

_LOG: Final = logging.getLogger("watchtower.portal.access")

_SESSION_COOKIE_KEY: Final[str] = "sid"


# ---------------------------------------------------------------------------
# Access logging + request identification
# ---------------------------------------------------------------------------
def _start_request() -> None:
    g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    g.request_started_at = time.monotonic()


def _finish_request(response: Any) -> Any:
    started = getattr(g, "request_started_at", None)
    duration_ms = int((time.monotonic() - started) * 1000) if started else -1
    response.headers.setdefault("X-Request-ID", getattr(g, "request_id", ""))
    _LOG.info(
        "access method=%s path=%s status=%s duration_ms=%s ip=%s rid=%s",
        request.method,
        request.path,
        response.status_code,
        duration_ms,
        request.remote_addr,
        getattr(g, "request_id", ""),
    )
    return response


# ---------------------------------------------------------------------------
# Authentication resolution (session cookie OR API key)
# ---------------------------------------------------------------------------
def _resolve_identity() -> None:
    """Populate ``g.principal`` and ``g.auth_kind`` from request context."""
    g.principal = None
    g.auth_kind = None

    api_key = request.headers.get("X-API-Key")
    if not api_key:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            api_key = auth_hdr[7:].strip()
    if api_key:
        try:
            principal = _apikey.validate_api_key(api_key)
        except AuthFailure:
            principal = None
        if principal:
            g.principal = principal
            g.auth_kind = "api_key"
            return

    sid = session.get(_SESSION_COOKIE_KEY)
    if sid:
        try:
            principal = _session.get_session(sid)
        except AuthFailure:
            principal = None
        if principal:
            g.principal = principal
            g.auth_kind = "session"


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    """Deny access when no authenticated principal is attached to ``g``."""

    @functools.wraps(view)
    def _wrapped(*args: Any, **kwargs: Any) -> Any:
        if getattr(g, "principal", None) is None:
            abort(401)
        return view(*args, **kwargs)

    return _wrapped


def role_required(*roles: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Require the principal to hold at least one of ``roles``."""

    def _decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            principal = getattr(g, "principal", None)
            if principal is None:
                abort(401)
            if not _rbac.has_any_role(principal, list(roles)):
                abort(403)
            return view(*args, **kwargs)

        return _wrapped

    return _decorator


# ---------------------------------------------------------------------------
# Rate limiting hook (portal-local, per-key sliding window)
# ---------------------------------------------------------------------------
class _SlidingWindow:
    """Thread-safe sliding-window counter used by ``rate_limit``."""

    def __init__(self, capacity: int, window_seconds: float) -> None:
        self._capacity = capacity
        self._window = window_seconds
        self._events: dict[str, Deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            bucket = self._events.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self._capacity:
                return False
            bucket.append(now)
            return True


def rate_limit(
    capacity: int, per_seconds: float, key_fn: Optional[Callable[[], str]] = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Sliding-window rate-limit decorator.

    Args:
        capacity: Maximum number of allowed requests per window.
        per_seconds: Sliding window duration in seconds.
        key_fn: Optional callable returning the bucket key. Defaults to
            principal id if authenticated, otherwise the remote address.
    """
    window = _SlidingWindow(capacity, per_seconds)

    def _default_key() -> str:
        principal = getattr(g, "principal", None)
        if principal is not None:
            pid = getattr(principal, "id", None) or getattr(principal, "username", None)
            if pid:
                return f"p:{pid}"
        return f"ip:{request.remote_addr or 'unknown'}"

    def _decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            key = (key_fn or _default_key)()
            if not window.allow(key):
                abort(429)
            return view(*args, **kwargs)

        return _wrapped

    return _decorator


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
def register_middleware(app: Flask) -> None:
    """Attach access logging and identity resolution to ``app``."""
    app.before_request(_start_request)
    app.before_request(_resolve_identity)
    app.after_request(_finish_request)


__all__ = [
    "register_middleware",
    "login_required",
    "role_required",
    "rate_limit",
]
