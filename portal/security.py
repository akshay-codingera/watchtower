"""Portal-level security primitives: CSRF, CSP, cookie flags.

Business-level authentication is delegated to ``sentinel_gate.*``. This
module only wires HTTP-layer defenses onto the Flask application.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from typing import Final

from flask import Flask, Response, abort, current_app, g, request, session

_LOG: Final = logging.getLogger(__name__)

_CSRF_SESSION_KEY: Final[str] = "_csrf_token"
_CSRF_HEADER: Final[str] = "X-CSRF-Token"
_CSRF_FORM_FIELD: Final[str] = "csrf_token"
_UNSAFE_METHODS: Final[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def issue_csrf_token() -> str:
    """Return the current session CSRF token, generating one if missing."""
    token = session.get(_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = token
    return token


def _extract_submitted_token() -> str | None:
    token = request.headers.get(_CSRF_HEADER)
    if token:
        return token
    if request.is_json:
        return None
    return request.form.get(_CSRF_FORM_FIELD)


def _csrf_before_request() -> None:
    """Verify CSRF token on state-changing requests.

    API key-authenticated requests (``Authorization: Bearer`` or
    ``X-API-Key``) are exempt because they are not browser sessions.
    """
    if request.method not in _UNSAFE_METHODS:
        return
    if request.headers.get("X-API-Key") or request.headers.get("Authorization"):
        return
    expected = session.get(_CSRF_SESSION_KEY)
    submitted = _extract_submitted_token()
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        _LOG.warning("CSRF rejection: path=%s ip=%s", request.path, request.remote_addr)
        abort(403, description="CSRF token missing or invalid")


def _apply_security_headers(response: Response) -> Response:
    csp = current_app.config.get(
        "CONTENT_SECURITY_POLICY",
        (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if current_app.config.get("SESSION_COOKIE_SECURE", False):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


def _inject_csrf_into_g() -> None:
    g.csrf_token = issue_csrf_token()


def register_security(app: Flask) -> None:
    """Attach CSRF verification, CSP and secure cookie flags to ``app``."""
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault(
        "SESSION_COOKIE_SECURE", bool(app.config.get("PORTAL_HTTPS", False))
    )
    app.before_request(_inject_csrf_into_g)
    app.before_request(_csrf_before_request)
    app.after_request(_apply_security_headers)

    @app.context_processor
    def _csrf_context() -> dict[str, str]:
        return {"csrf_token": issue_csrf_token()}
