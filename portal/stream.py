"""Server-Sent Events endpoint for the Watchtower portal.

The portal never generates events on its own. It subscribes to the
``dispatch.notifier.browser`` hub, which is the canonical fan-out for
log / alert / stats events produced by the pipeline and dispatch layers.

Event kinds emitted:

    heartbeat   periodic keep-alive
    log         a new normalised LogRecord entered the ledger
    alert       an incident state transition
    stats       telemetry snapshot
    disconnect  server-initiated close (used on graceful shutdown)

Reconnect is supported via the ``Last-Event-ID`` header. Multiple
concurrent clients are supported and each gets an isolated queue.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Final, Iterator

from flask import Blueprint, Response, current_app, g, request, stream_with_context

from dispatch.notifier import browser as _browser  # type: ignore[import-not-found]
from nucleus.telemetry import metrics as telemetry  # type: ignore[import-not-found]

from portal.middleware import login_required

_LOG: Final = logging.getLogger(__name__)

bp = Blueprint("stream", __name__, url_prefix="/stream")

_HEARTBEAT_SECONDS: Final[float] = 15.0
_STATS_SECONDS: Final[float] = 5.0
_QUEUE_GET_TIMEOUT: Final[float] = 1.0


def _sse_pack(event: str, data: Any, event_id: str | None = None) -> str:
    """Encode a Python object as an SSE frame."""
    body = json.dumps(data, default=str, separators=(",", ":"))
    lines = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    for line in body.splitlines() or [body]:
        lines.append(f"data: {line}")
    lines.append("")
    lines.append("")
    return "\n".join(lines)


class _ShutdownFlag:
    """Application-scoped flag toggled on graceful shutdown."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def trip(self) -> None:
        self._event.set()

    @property
    def is_set(self) -> bool:
        return self._event.is_set()


def install_shutdown_flag(app: Any) -> None:
    """Attach a ``_ShutdownFlag`` to the app for SSE cleanup."""
    app.extensions.setdefault("portal_sse_shutdown", _ShutdownFlag())


def trip_shutdown(app: Any) -> None:
    """Signal all live SSE streams to close cleanly."""
    flag = app.extensions.get("portal_sse_shutdown")
    if isinstance(flag, _ShutdownFlag):
        flag.trip()


def _iter_events(
    subscription_queue: "queue.Queue[dict[str, Any]]",
    shutdown: _ShutdownFlag,
    last_event_id: str | None,
) -> Iterator[str]:
    """Yield SSE frames until client disconnects or shutdown."""
    counter = int(last_event_id) if last_event_id and last_event_id.isdigit() else 0
    last_heartbeat = time.monotonic()
    last_stats = 0.0

    # Initial hello frame so clients can validate the stream immediately.
    counter += 1
    yield _sse_pack(
        "heartbeat", {"ts": time.time(), "resumed_from": last_event_id}, str(counter)
    )

    while not shutdown.is_set:
        try:
            payload = subscription_queue.get(timeout=_QUEUE_GET_TIMEOUT)
        except queue.Empty:
            payload = None

        if payload is not None:
            counter += 1
            kind = str(payload.get("kind", "log"))
            yield _sse_pack(kind, payload.get("data", {}), str(counter))

        now = time.monotonic()
        if now - last_heartbeat >= _HEARTBEAT_SECONDS:
            counter += 1
            yield _sse_pack("heartbeat", {"ts": time.time()}, str(counter))
            last_heartbeat = now

        if now - last_stats >= _STATS_SECONDS:
            counter += 1
            try:
                snap = telemetry.snapshot()
            except Exception:  # pragma: no cover - defensive
                _LOG.exception("telemetry snapshot failed")
                snap = {}
            yield _sse_pack("stats", snap, str(counter))
            last_stats = now

    counter += 1
    yield _sse_pack("disconnect", {"reason": "server_shutdown"}, str(counter))


@bp.get("")
@login_required
def stream() -> Response:
    """Open a Server-Sent Events stream for the current principal."""
    shutdown = current_app.extensions.get("portal_sse_shutdown")
    if not isinstance(shutdown, _ShutdownFlag):
        shutdown = _ShutdownFlag()
        current_app.extensions["portal_sse_shutdown"] = shutdown

    subscription = _browser.subscribe()
    last_event_id = request.headers.get("Last-Event-ID")
    principal_id = getattr(getattr(g, "principal", None), "id", "anonymous")
    _LOG.info("SSE open principal=%s resume=%s", principal_id, last_event_id)

    @stream_with_context
    def _generate() -> Iterator[str]:
        try:
            yield from _iter_events(subscription, shutdown, last_event_id)
        finally:
            try:
                _browser.unsubscribe(subscription)
            except Exception:  # pragma: no cover - defensive
                _LOG.exception("SSE unsubscribe failed")
            _LOG.info("SSE close principal=%s", principal_id)

    response = Response(_generate(), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response


__all__ = ["bp", "install_shutdown_flag", "trip_shutdown"]
