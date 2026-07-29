#!/usr/bin/env python3
"""
core.py
=======
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

Entrypoint. Wires together every layer in dependency order:

    config → vault (DB + migrations) → conduit → intake listeners
           → ingest workers → (scheduler, portal — not built yet)

Current state of the build (see the file-priority tree in the project
doc): nucleus, intake, and ledger exist. pipeline/sieve+forge (real
format parsing), portal (the Flask dashboard), scheduler, and the rest
are not built yet. So that the system is runnable end-to-end today,
this file includes a PLACEHOLDER ingest worker that takes records
straight off the conduit and writes them to the ledger with minimal
processing (log_category guessed from facility, integrity-sealed).

    ⚠ REPLACE ME: once pipeline/sieve.py + pipeline/marshal.py exist,
    swap `_placeholder_process()` below for a call into the real
    pipeline (sieve.detect_format → forge parser → marshal.normalize
    → sentinel.validate/seal → scribe.write). Nothing else in this
    file needs to change — the ingest workers just call whatever
    `process(record) -> LogRecord` function pipeline exposes.

Run with:
    python core.py
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time

from nucleus.config import cfg
from nucleus.constants import FACILITY_TO_CATEGORY, LogCategory
from nucleus.exceptions import WatchtowerError
from nucleus.record import LogRecord
from nucleus.telemetry import metrics

from intake.conduit import Conduit
from intake.intake_metrics import IntakeMetricsLogger
from intake.listener import UDPListener
from intake.ratelimiter import RateLimiter
from intake.tls_listener import TCPListener

from ledger.vault import Vault
from ledger.scribe import Scribe

logger = logging.getLogger("watchtower.core")

# Number of threads pulling off the conduit and writing to the ledger.
# One is plenty until real parsing work (pipeline) makes each record
# more expensive to process.
_INGEST_WORKER_COUNT = 2


# ── Logging setup ─────────────────────────────────────────────────────────────

def _configure_logging() -> None:
    level_name = cfg.server.log_level if cfg is not None else "INFO"
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# ── Placeholder ingest processing (see module docstring) ──────────────────────

def _placeholder_process(record: LogRecord) -> LogRecord:
    """
    Minimal, non-parsing normalization step standing in for the real
    pipeline (sieve/forge/marshal/sentinel).

    - Best-effort log_category from the facility name, if a real
      parser has already set one; otherwise falls back to SYSTEM.
    - Seals the record so scribe.write()'s integrity/dedup constraint
      has something to check against.

    This intentionally does NOT attempt to parse `raw_message` into
    structured fields (hostname, app_name, severity, etc.) — that is
    real parsing work that belongs in pipeline/forge/*, not here.
    """
    if not record.log_category:
        record.log_category = FACILITY_TO_CATEGORY.get(
            record.facility, LogCategory.SYSTEM
        )
    record.seal()
    return record


# ── Ingest workers ──────────────────────────────────────────────────────────

class IngestWorker:
    """
    Pulls LogRecords off the conduit, runs them through processing,
    and writes them to the ledger. Runs in its own daemon thread.
    """

    def __init__(self, worker_id: int, conduit: Conduit, scribe: Scribe):
        self._id = worker_id
        self._conduit = conduit
        self._scribe = scribe
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"ingest-worker-{self._id}", daemon=True
        )
        self._thread.start()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        logger.info("Ingest worker %d started", self._id)
        for record in self._conduit.consume(timeout=1.0):
            try:
                processed = _placeholder_process(record)
                self._scribe.write(processed)
            except WatchtowerError as exc:
                logger.warning("Ingest worker %d: failed to store record: %s", self._id, exc)
            except Exception:
                logger.exception("Ingest worker %d: unexpected error", self._id)
        logger.info("Ingest worker %d stopped", self._id)


# ── Application ────────────────────────────────────────────────────────────

class WatchtowerApp:
    """Owns the lifecycle of every long-running component."""

    def __init__(self):
        if cfg is None:
            raise SystemExit(
                "config.ini not found or invalid. Copy config.ini to the "
                "project root and fill in your values before starting WATCHTOWER."
            )

        self.vault = Vault(cfg.ledger.db_path)
        self.scribe: Scribe | None = None

        self.conduit = Conduit(maxsize=cfg.intake.queue_size)
        self.rate_limiter = RateLimiter(cfg.intake.rate_limit)

        self.udp_listener = UDPListener(self.conduit, rate_limiter=self.rate_limiter)
        self.tcp_listener = TCPListener(self.conduit, tls=False, rate_limiter=self.rate_limiter)
        self.tls_listener: TCPListener | None = (
            TCPListener(self.conduit, tls=True, rate_limiter=self.rate_limiter)
            if cfg.intake.tls_enabled else None
        )

        self.metrics_logger = IntakeMetricsLogger()
        self.ingest_workers: list[IngestWorker] = []
        self.portal_thread: threading.Thread | None = None

        self._stop_event = threading.Event()

    # ── Startup ──────────────────────────────────────────────────────────

    def start(self) -> None:
        logger.info("Starting %s (%s)", cfg.server.name, cfg.server.environment)

        logger.info("Initialising ledger at %s", cfg.ledger.db_path)
        self.vault.initialise()
        self.scribe = Scribe(self.vault)

        self.udp_listener.start()
        self.tcp_listener.start()
        if self.tls_listener is not None:
            self.tls_listener.start()
        else:
            logger.info("TLS intake disabled (intake.tls_enabled=false in config.ini)")

        self.ingest_workers = [
            IngestWorker(i, self.conduit, self.scribe)
            for i in range(_INGEST_WORKER_COUNT)
        ]
        for worker in self.ingest_workers:
            worker.start()

        self.metrics_logger.start()

        # ⚠ scheduler/ (retention, backups, digests) is still not wired in.
        #   from scheduler.clock import Clock
        #   self.clock = Clock(); self.clock.start()
        from portal.gate import create_app
        portal_app = create_app()

        def _run_portal() -> None:
            portal_app.run(
                host=cfg.portal.host,
                port=cfg.portal.port,
                debug=False,
                use_reloader=False,
                threaded=True,
            )

        self.portal_thread = threading.Thread(
            target=_run_portal, name="portal", daemon=True
        )
        self.portal_thread.start()

        logger.info(
            "WATCHTOWER is up — UDP %s:%d, TCP %s:%d%s",
            cfg.intake.udp_host, cfg.intake.udp_port,
            cfg.intake.udp_host, cfg.intake.tcp_port,
            f", TLS {cfg.intake.udp_host}:{cfg.intake.tls_port}" if self.tls_listener else "",
        )
        logger.info(
            "Dashboard: http://%s:%d/  (login with the [auth] admin_password_hash from config.ini)",
            "localhost" if cfg.portal.host in ("0.0.0.0", "") else cfg.portal.host,
            cfg.portal.port,
        )

    # ── Shutdown ─────────────────────────────────────────────────────────

    def stop(self) -> None:
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        logger.info("Shutting down WATCHTOWER...")

        self.udp_listener.stop()
        self.tcp_listener.stop()
        if self.tls_listener is not None:
            self.tls_listener.stop()
        self.metrics_logger.stop()

        self.udp_listener.join(timeout=5)
        self.tcp_listener.join(timeout=5)
        if self.tls_listener is not None:
            self.tls_listener.join(timeout=5)

        # Let ingest workers drain whatever is already queued before
        # closing the sentinel, so nothing already accepted is lost.
        self.conduit.shutdown()
        for worker in self.ingest_workers:
            worker.join(timeout=10)

        self.vault.shutdown()
        logger.info("WATCHTOWER stopped cleanly.")

    def run_forever(self) -> None:
        self.start()

        def _handle_signal(signum, _frame):
            logger.info("Received signal %s", signum)
            self.stop()

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()


def main() -> int:
    _configure_logging()
    app = WatchtowerApp()
    app.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())