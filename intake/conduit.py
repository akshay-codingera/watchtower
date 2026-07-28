"""
intake/conduit.py
==================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

The conduit is the single hand-off point between the receiving layer
(listener.py, tls_listener.py) and everything downstream that consumes
records (pipeline.sieve, or the placeholder ingest worker in core.py
until pipeline exists).

Design principle: listeners never block on downstream work. A listener
thread's only job is "get bytes off the wire as fast as possible".
If the conduit is full, that means downstream can't keep up — the
record is dropped and counted, not blocked on.

Thread-safety: built on queue.Queue, which is already thread-safe.
This module adds WATCHTOWER-specific bookkeeping on top: telemetry,
a typed drop exception, and a clean shutdown signal so worker threads
know when to stop pulling.
"""

from __future__ import annotations

import queue
import threading
from typing import Optional

from nucleus.config import cfg
from nucleus.exceptions import ConduitFullError
from nucleus.record import LogRecord
from nucleus.telemetry import metrics

# Sentinel placed on the queue to wake blocked consumers on shutdown.
_SHUTDOWN = object()


class Conduit:
    """
    Thread-safe, bounded, single queue between intake and the
    downstream consumer.

    Usage:
        conduit = Conduit()

        # producer side (listener.py)
        conduit.put(record)                # raises ConduitFullError if full

        # consumer side (core.py ingest worker / pipeline)
        for record in conduit.consume():
            ...
        # or manually:
        record = conduit.get(timeout=1.0)  # None on timeout or shutdown
    """

    def __init__(self, maxsize: Optional[int] = None):
        size = maxsize if maxsize is not None else (
            cfg.intake.queue_size if cfg is not None else 10000
        )
        self._q: "queue.Queue[object]" = queue.Queue(maxsize=size)
        self._shutdown = threading.Event()

    # ── Producer side ──────────────────────────────────────────────────────

    def put(self, record: LogRecord) -> None:
        """
        Push a record onto the queue. Never blocks.

        Raises:
            ConduitFullError: queue is at capacity — caller (listener)
                should count this as a drop and move on immediately.
        """
        try:
            self._q.put_nowait(record)
        except queue.Full as exc:
            metrics.intake_packets_dropped.increment()
            raise ConduitFullError(
                "Conduit queue is full — downstream cannot keep up",
                {"depth": self._q.qsize()},
            ) from exc
        metrics.intake_queue_depth.set(self._q.qsize())

    # ── Consumer side ──────────────────────────────────────────────────────

    def get(self, timeout: float = 1.0) -> Optional[LogRecord]:
        """
        Pop the next record, waiting up to `timeout` seconds.

        Returns None on timeout OR after shutdown() has been called and
        the queue has drained — callers should treat None as "check the
        shutdown flag and loop again", not as an error.
        """
        try:
            item = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        finally:
            metrics.intake_queue_depth.set(self._q.qsize())

        if item is _SHUTDOWN:
            # Re-post so *other* consumer threads also wake up and exit.
            self._q.put(_SHUTDOWN)
            return None
        return item  # type: ignore[return-value]

    def consume(self, timeout: float = 1.0):
        """Generator form of get() — stops cleanly once shutdown fires."""
        while not self.is_shutdown():
            record = self.get(timeout=timeout)
            if record is not None:
                yield record

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def shutdown(self) -> None:
        """
        Signal all consumers to stop. Safe to call multiple times.
        Existing queued records are still consumable after this call;
        the sentinel just tells consume()/get() to eventually return None.
        """
        if not self._shutdown.is_set():
            self._shutdown.set()
            self._q.put(_SHUTDOWN)

    def is_shutdown(self) -> bool:
        return self._shutdown.is_set()

    def qsize(self) -> int:
        return self._q.qsize()

    def __len__(self) -> int:
        return self.qsize()