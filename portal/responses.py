"""Uniform JSON response envelope for the Watchtower portal API.

Every API response emitted by the portal MUST use these helpers so that
clients can rely on a stable ``{success, data|error}`` contract.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from flask import Response, jsonify


def ok(data: Optional[Any] = None, status: int = 200) -> Tuple[Response, int]:
    """Return a successful JSON response.

    Args:
        data: Payload to return under the ``data`` key. ``None`` becomes ``{}``.
        status: HTTP status code (default ``200``).

    Returns:
        Flask ``(Response, status)`` tuple.
    """
    payload: Mapping[str, Any] = {"success": True, "data": data if data is not None else {}}
    return jsonify(payload), status


def fail(
    code: str,
    message: str,
    status: int = 400,
    details: Optional[Mapping[str, Any]] = None,
) -> Tuple[Response, int]:
    """Return a failure JSON response.

    Args:
        code: Machine-readable error code (e.g. ``"validation_error"``).
        message: Human-readable message. Must never leak stack traces.
        status: HTTP status code (default ``400``).
        details: Optional extra structured context.

    Returns:
        Flask ``(Response, status)`` tuple.
    """
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = dict(details)
    return jsonify({"success": False, "error": error}), status
