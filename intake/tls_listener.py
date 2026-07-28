"""
intake/tls_listener.py
=======================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

TCP syslog receiver, with optional TLS (RFC 5425, port 6514).

Most devices on a small/medium network speak UDP, but a few things
benefit from TCP: reliable delivery for compliance-sensitive auth
logs, or messages too large for a single UDP datagram. TLS on top of
that is for anything crossing an untrusted network segment.

One class, two modes:
    TCPListener(conduit, tls=False)  → plain TCP on cfg.intake.tcp_port
    TCPListener(conduit, tls=True)   → TLS on cfg.intake.tls_port,
                                        using cfg.intake.tls_cert/tls_key

Each accepted connection gets its own handler thread with its own
TCPFramer instance (framing state — octet-counting vs newline — is
per-connection, never shared).
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading

from nucleus.config import cfg
from nucleus.constants import Transport
from nucleus.exceptions import ConduitFullError, RateLimitExceeded, SocketBindError
from nucleus.record import LogRecord
from nucleus.telemetry import metrics

from intake.conduit import Conduit
from intake.framer import FramingError, TCPFramer
from intake.ratelimiter import RateLimiter

logger = logging.getLogger(__name__)

_ACCEPT_POLL_TIMEOUT = 1.0
_RECV_CHUNK_SIZE = 4096


class TCPListener:
    """
    Accepts TCP (optionally TLS-wrapped) syslog connections and frames
    each connection's byte stream into individual messages.

    Usage:
        # plain TCP
        tcp = TCPListener(conduit, tls=False)
        tcp.start()

        # TLS (RFC 5425) — only if cfg.intake.tls_enabled
        tls = TCPListener(conduit, tls=True)
        tls.start()
    """

    def __init__(
        self,
        conduit: Conduit,
        tls: bool = False,
        host: str | None = None,
        port: int | None = None,
        rate_limiter: RateLimiter | None = None,
    ):
        self._conduit = conduit
        self._tls = tls
        self._host = host if host is not None else (
            cfg.intake.udp_host if cfg is not None else "0.0.0.0"
        )
        if port is not None:
            self._port = port
        elif cfg is not None:
            self._port = cfg.intake.tls_port if tls else cfg.intake.tcp_port
        else:
            self._port = Transport.TLS_PORT if tls else Transport.TCP_PORT

        self._limiter = rate_limiter if rate_limiter is not None else RateLimiter()

        self._sock: socket.socket | None = None
        self._ssl_context: ssl.SSLContext | None = None
        self._stop_event = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._conn_threads: list[threading.Thread] = []
        self._lock = threading.Lock()

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._tls:
            self._ssl_context = self._build_ssl_context()
        self._sock = self._bind_socket()
        self._stop_event.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"{'tls' if self._tls else 'tcp'}-listener-{self._port}",
            daemon=True,
        )
        self._accept_thread.start()
        logger.info(
            "%s listener started on %s:%d",
            "TLS" if self._tls else "TCP", self._host, self._port,
        )

    def stop(self) -> None:
        self._stop_event.set()

    def join(self, timeout: float | None = None) -> None:
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=timeout)
        with self._lock:
            threads = list(self._conn_threads)
        for t in threads:
            t.join(timeout=timeout)

    def is_running(self) -> bool:
        return self._accept_thread is not None and self._accept_thread.is_alive()

    # ── Socket / TLS setup ────────────────────────────────────────────────

    def _build_ssl_context(self) -> ssl.SSLContext:
        cert = cfg.intake.tls_cert if cfg is not None else ""
        key = cfg.intake.tls_key if cfg is not None else ""
        if not cert or not key:
            raise SocketBindError(
                "TLS enabled but tls_cert/tls_key not set in config.ini [intake]"
            )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.load_cert_chain(certfile=cert, keyfile=key)
        except (ssl.SSLError, OSError) as exc:
            raise SocketBindError(f"Failed to load TLS cert/key: {exc}") from exc
        return context

    def _bind_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self._host, self._port))
            sock.listen(128)
        except OSError as exc:
            raise SocketBindError(
                f"Failed to bind TCP socket to {self._host}:{self._port}: {exc}",
                {"host": self._host, "port": self._port},
            ) from exc
        sock.settimeout(_ACCEPT_POLL_TIMEOUT)
        return sock

    # ── Accept loop ────────────────────────────────────────────────────────

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                client_sock, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                continue

            if self._tls:
                try:
                    client_sock = self._ssl_context.wrap_socket(
                        client_sock, server_side=True
                    )
                except ssl.SSLError as exc:
                    logger.warning("TLS handshake failed for %s: %s", addr, exc)
                    client_sock.close()
                    continue

            metrics.intake_tcp_connections.increment()
            t = threading.Thread(
                target=self._handle_connection,
                args=(client_sock, addr),
                daemon=True,
            )
            with self._lock:
                self._conn_threads.append(t)
            t.start()

        self._sock.close()
        logger.info(
            "%s listener on port %d stopped",
            "TLS" if self._tls else "TCP", self._port,
        )

    # ── Per-connection handling ──────────────────────────────────────────

    def _handle_connection(self, client_sock: socket.socket, addr: tuple) -> None:
        sender_ip, sender_port = addr[0], addr[1]
        framer = TCPFramer()
        transport = "tls" if self._tls else "tcp"
        client_sock.settimeout(_ACCEPT_POLL_TIMEOUT)

        try:
            while not self._stop_event.is_set():
                try:
                    chunk = client_sock.recv(_RECV_CHUNK_SIZE)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break  # peer closed the connection

                metrics.intake_bytes_received.increment(len(chunk))

                try:
                    for message in framer.feed(chunk):
                        self._handle_message(message, sender_ip, sender_port, transport)
                except FramingError as exc:
                    logger.warning("Framing error from %s: %s — closing connection", sender_ip, exc)
                    break
        finally:
            metrics.intake_tcp_connections.decrement()
            try:
                client_sock.close()
            except OSError:
                pass
            with self._lock:
                current = threading.current_thread()
                if current in self._conn_threads:
                    self._conn_threads.remove(current)

    def _handle_message(self, message: str, sender_ip: str, sender_port: int, transport: str) -> None:
        metrics.intake_packets_received.increment()
        metrics.intake_rate.increment()

        try:
            self._limiter.check(sender_ip)
        except RateLimitExceeded:
            metrics.intake_packets_dropped.increment()
            logger.debug("Dropped message from %s: rate limit exceeded", sender_ip)
            return

        record = LogRecord.from_raw(
            raw=message,
            sender_ip=sender_ip,
            sender_port=sender_port,
            transport=transport,
        )

        try:
            self._conduit.put(record)
        except ConduitFullError:
            logger.warning(
                "Conduit full — dropping message from %s (queue depth=%d)",
                sender_ip, self._conduit.qsize(),
            )