"""
dispatch/notifier/browser.py
==============================
WATCHTOWER — Browser (SSE) Notifier

Not a real network channel — this is the bridge between dispatch/ and
portal/stream.py's Server-Sent Events endpoint. Every dashboard tab
open in a browser subscribes to a queue.Queue here; notify() pushes
the alert onto every currently-subscribed queue.

Design principle: this notifier can never "fail" the way email/webhook/
telegram can — there's no network call, just an in-process queue push.
It never raises NotificationError; if there are zero subscribers
(nobody has the dashboard open), that's not a delivery failure, it's
just nobody there to see it live — the alert is still in alert_history
for when someone opens the page.

portal/stream.py wires up like this (once built):
    @app.route("/api/stream")
    def stream():
        q = browser_notifier.subscribe()
        def gen():
            try:
                while True:
                    yield f"data: {q.get()}\n\n"
            finally:
                browser_notifier.unsubscribe(q)
        return Response(gen(), mimetype="text/event-stream")
"""

from __future__ import annotations

import json
import logging
import queue
import threading

from nucleus.record import AlertRecord
from nucleus.telemetry import metrics
from dispatch.notifier import Notifier
from dispatch.rulebook import AlertRule

logger = logging.getLogger(__name__)

# Cap per-subscriber queue depth so one stalled/closed browser tab that
# never drains its queue can't grow unbounded memory usage.
_MAX_QUEUE_DEPTH = 200


class BrowserNotifier(Notifier):
    """In-memory SSE fan-out for live dashboard alerts."""

    channel_name = "browser"

    def __init__(self) -> None:
        self._subscribers: set[queue.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        """Called by portal/stream.py when a browser opens the SSE endpoint."""
        q: queue.Queue = queue.Queue(maxsize=_MAX_QUEUE_DEPTH)
        with self._lock:
            self._subscribers.add(q)
        metrics.portal_sse_subscribers.set(len(self._subscribers))
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Called by portal/stream.py when the SSE connection closes."""
        with self._lock:
            self._subscribers.discard(q)
        metrics.portal_sse_subscribers.set(len(self._subscribers))

    def notify(self, alert: AlertRecord, rule: AlertRule) -> None:
        """
        Push the alert to every subscribed browser tab. Never raises —
        a full subscriber queue (stalled tab) is dropped silently
        rather than blocking or failing the whole dispatch.
        """
        payload = json.dumps({
            "type":      "alert",
            "level":     alert.level,
            "rule_name": rule.name,
            "reason":    alert.reason,
            "device_ip": alert.device_ip,
            "fired_at":  alert.fired_at,
        })

        with self._lock:
            subscribers = list(self._subscribers)

        for q in subscribers:
            try:
                q.put_nowait(payload)
            except queue.Full:
                logger.warning("Dropped alert push — subscriber queue full (stalled tab?)")