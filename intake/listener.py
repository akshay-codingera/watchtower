"""
intake/listener.py
===================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

The UDP syslog receiver. This is where the vast majority of devices
(switches, routers, APs, firewalls without TCP/TLS support) land —
UDP 514-class ports are what DHCP Option 7 points devices at.

Design principle: this thread does the absolute minimum work possible
per packet. No parsing, no format detection — that's pipeline's job.
The listener's contract is just:

    bytes off the wire → rate-limit check → LogRecord.from_raw() → conduit.put()

If any step fails, the packet is counted and dropped; the loop never
raises out to the caller and never blocks on a slow downstream.

Runs in its own daemon thread, started by core.py. Call stop() (or
just let the process exit — it's a daemon thread) to shut down; the
loop polls a threading.Event with a socket timeout so it notices
shutdown within one poll interval instead of blocking forever on
recvfrom().
"""

from __future__ import annotations

import logging
import socket
import threading

from nucleus.config import cfg
from nucleus.constants import Transport
from nucleus.exceptions import ConduitFullError, RateLimitExceeded, SocketBindError
from nucleus.record import LogRecord
from nucleus.telemetry import metrics

from intake.conduit import Conduit
from intake.ratelimiter import RateLimiter

logger = logging.getLogger(__name__)

# How often the recv loop wakes up to check the stop flag, in seconds.
_POLL_TIMEOUT = 1.0


class UDPListener:
    """
    Non-blocking (poll-timeout based) UDP syslog receiver.

    Usage:
        conduit  = Conduit()
        listener = UDPListener(conduit)
        listener.start()          # spawns a daemon thread, returns immediately
        ...
        listener.stop()           # signals the thread to exit
        listener.join(timeout=5)
    """

    def __init__(
        self,
        conduit: Conduit,
        host: str | None = None,
        port: int | None = None,
        rate_limiter: RateLimiter | None = None,
    ):
        self._conduit = conduit
        self._host = host if host is not None else (
            cfg.intake.udp_host if cfg is not None else "0.0.0.0"
        )
        self._port = port if port is not None else (
            cfg.intake.udp_port if cfg is not None else Transport.UDP_PORT
        )
        self._recv_buffer_size = cfg.intake.recv_buffer if cfg is not None else 4194304
        self._limiter = rate_limiter if rate_limiter is not None else RateLimiter()

        self._sock: socket.socket | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind the socket and spawn the receive loop thread."""
        self._sock = self._bind_socket()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"udp-listener-{self._port}",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "UDP listener started on %s:%d", self._host, self._port
        )

    def stop(self) -> None:
        """Signal the receive loop to exit on its next poll."""
        self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Internals ──────────────────────────────────────────────────────────

    def _bind_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, self._recv_buffer_size
            )
        except OSError:
            # Not fatal — kernel just keeps its default; log and continue.
            logger.warning(
                "Could not set SO_RCVBUF to %d, using OS default",
                self._recv_buffer_size,
            )
        try:
            sock.bind((self._host, self._port))
        except OSError as exc:
            raise SocketBindError(
                f"Failed to bind UDP socket to {self._host}:{self._port}: {exc}",
                {"host": self._host, "port": self._port},
            ) from exc
        sock.settimeout(_POLL_TIMEOUT)
        return sock

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                raw_bytes, addr = self._sock.recvfrom(Transport.MAX_UDP_SIZE)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                metrics.intake_udp_errors.increment()
                logger.warning("UDP recv error: %s", exc)
                continue

            self._handle_packet(raw_bytes, addr)

        self._sock.close()
        logger.info("UDP listener on port %d stopped", self._port)

    def _handle_packet(self, raw_bytes: bytes, addr: tuple) -> None:
        sender_ip, sender_port = addr[0], addr[1]

        metrics.intake_packets_received.increment()
        metrics.intake_bytes_received.increment(len(raw_bytes))
        metrics.intake_rate.increment()

        try:
            self._limiter.check(sender_ip)
        except RateLimitExceeded:
            metrics.intake_packets_dropped.increment()
            logger.debug("Dropped packet from %s: rate limit exceeded", sender_ip)
            return

        try:
            message = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            metrics.intake_packets_dropped.increment()
            logger.debug("Dropped unparseable UDP packet from %s", sender_ip)
            return

        record = LogRecord.from_raw(
            raw=message,
            sender_ip=sender_ip,
            sender_port=sender_port,
            transport="udp",
        )

        try:
            self._conduit.put(record)
        except ConduitFullError:
            logger.warning(
                "Conduit full — dropping packet from %s (queue depth=%d)",
                sender_ip, self._conduit.qsize(),
            )