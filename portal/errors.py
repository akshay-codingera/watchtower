"""Centralised HTTP error handlers for the Watchtower portal."""

from __future__ import annotations

import logging
from typing import Any, Final

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from nucleus.exceptions import (  # type: ignore[import-not-found]
    AuthError,
    ParseError,
    RateLimitExceeded,
)

from portal.responses import fail

_LOG: Final = logging.getLogger(__name__)


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.accept_mimetypes
    return accept.best == "application/json" or accept["application/json"] > accept["text/html"]


def _render_error(status: int, code: str, message: str) -> tuple[Response, int]:
    if _wants_json():
        return fail(code, message, status=status)
    body = render_template("shell.html", error={"status": status, "message": message})
    return Response(body, status=status, mimetype="text/html"), status


def register_error_handlers(app: Flask) -> None:
    """Attach uniform error handlers to ``app``."""

    @app.errorhandler(400)
    def _bad_request(exc: HTTPException) -> Any:
        return _render_error(400, "bad_request", exc.description or "Bad request")

    @app.errorhandler(401)
    def _unauthorized(exc: HTTPException) -> Any:
        return _render_error(401, "unauthorized", exc.description or "Authentication required")

    @app.errorhandler(403)
    def _forbidden(exc: HTTPException) -> Any:
        return _render_error(403, "forbidden", exc.description or "Forbidden")

    @app.errorhandler(404)
    def _not_found(exc: HTTPException) -> Any:
        return _render_error(404, "not_found", exc.description or "Resource not found")

    @app.errorhandler(405)
    def _method_not_allowed(exc: HTTPException) -> Any:
        return _render_error(
            405, "method_not_allowed", exc.description or "Method not allowed"
        )

    @app.errorhandler(413)
    def _payload_too_large(exc: HTTPException) -> Any:
        return _render_error(413, "payload_too_large", "Request payload too large")

    @app.errorhandler(429)
    def _too_many_requests(exc: HTTPException) -> Any:
        return _render_error(429, "rate_limited", exc.description or "Too many requests")

    @app.errorhandler(AuthError)
    def _auth_failure(exc: AuthError) -> Any:
        _LOG.info("Authentication failed: %s", exc)
        return _render_error(401, "auth_failure", "Authentication failed")

    @app.errorhandler(RateLimitExceeded)
    def _rate_limited(exc: RateLimitExceeded) -> Any:
        _LOG.warning("Rate limit exceeded: %s", exc)
        return _render_error(429, "rate_limited", "Too many requests")

    @app.errorhandler(ParseError)
    def _parse_error(exc: ParseError) -> Any:
        _LOG.info("Parse error: %s", exc)
        return _render_error(400, "parse_error", "Invalid input")

    @app.errorhandler(HTTPException)
    def _generic_http(exc: HTTPException) -> Any:
        return _render_error(
            exc.code or 500, "http_error", exc.description or "Request failed"
        )

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception) -> Any:  # pragma: no cover - defensive
        _LOG.exception("Unhandled portal exception: %s", exc)
        return _render_error(500, "internal_error", "Internal server error")

    @app.errorhandler(500)
    def _internal(exc: HTTPException) -> Any:
        return _render_error(500, "internal_error", "Internal server error")


__all__ = ["register_error_handlers"]
