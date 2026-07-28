"""
intake/framer.py
=================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

TCP syslog has no natural message boundary the way one UDP datagram
does — a single recv() can contain zero, one, or several messages,
and a message can be split across several recv() calls. The framer's
job is to turn a stream of arbitrary byte chunks back into complete
individual syslog messages.

Two framing styles are supported, per RFC 6587:

    1. Octet-counting  — "<len> <message>", e.g. b"48 <34>1 2024-...".
       The length prefix tells us exactly how many message bytes
       follow. This is the RFC 5425 (TLS) preferred framing and is
       unambiguous even if the message itself contains newlines.

    2. Newline-delimited — messages separated by \\n (or \\r\\n).
       This is what most legacy devices (Cisco IOS, older Fortinet
       firmware) actually send over plain TCP, despite it technically
       being non-transparent framing.

The framer auto-detects which style a connection is using from the
first bytes received and stays with it for the life of the connection.
"""

from __future__ import annotations

# Cap a single message at RFC5424_MAX to protect against a malformed
# or malicious octet-count header claiming an enormous length.
from nucleus.constants import Transport

_MAX_MESSAGE_BYTES = Transport.RFC5424_MAX


class FramingError(Exception):
    """Raised when the byte stream cannot be framed (corrupt length
    prefix, oversized message, etc). Caller should close the connection."""


class TCPFramer:
    """
    Stateful per-connection framer. Feed it raw bytes as they arrive
    from recv(); it yields complete decoded message strings as soon
    as each one is fully received.

    Usage:
        framer = TCPFramer()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            for message in framer.feed(chunk):
                handle(message)
    """

    def __init__(self):
        self._buffer: bytearray = bytearray()
        self._mode: str | None = None   # "octet" | "newline" | None (undetermined)

    def feed(self, data: bytes):
        """
        Append newly received bytes and yield every complete message
        that can now be extracted.

        Raises:
            FramingError: the stream is malformed beyond recovery.
        """
        if not data:
            return
        self._buffer.extend(data)

        if self._mode is None:
            self._mode = self._detect_mode()
            if self._mode is None:
                # Not enough bytes yet to tell — wait for more.
                return

        if self._mode == "octet":
            yield from self._drain_octet_counting()
        else:
            yield from self._drain_newline_delimited()

    # ── Mode detection ────────────────────────────────────────────────────

    def _detect_mode(self) -> str | None:
        """
        Octet-counting frames start with ASCII digits followed by a
        single space, e.g. b"142 <34>...". Anything else (starts with
        '<' for a PRI, or plain text) is treated as newline-delimited.
        """
        if not self._buffer:
            return None
        first = self._buffer[0:1]
        if first.isdigit():
            # Wait until we've seen the delimiting space (or enough
            # bytes to be confident this isn't octet-counting at all).
            if b" " in self._buffer[:10]:
                return "octet"
            if len(self._buffer) >= 10:
                # 10 digit chars with no space is not a sane length prefix.
                return "newline"
            return None  # keep waiting
        return "newline"

    # ── Octet-counting framing (RFC 6587 / RFC 5425) ───────────────────────

    def _drain_octet_counting(self):
        while True:
            space_idx = self._buffer.find(b" ")
            if space_idx == -1:
                if len(self._buffer) > 10:
                    raise FramingError("Octet-counting length prefix too long")
                return
            length_bytes = self._buffer[:space_idx]
            if not length_bytes.isdigit():
                raise FramingError(
                    f"Invalid octet-counting length prefix: {length_bytes!r}"
                )
            msg_len = int(length_bytes)
            if msg_len <= 0 or msg_len > _MAX_MESSAGE_BYTES:
                raise FramingError(f"Octet-counting length out of range: {msg_len}")

            start = space_idx + 1
            end   = start + msg_len
            if len(self._buffer) < end:
                return  # message not fully received yet

            raw = bytes(self._buffer[start:end])
            del self._buffer[:end]
            yield raw.decode("utf-8", errors="replace")

    # ── Newline-delimited framing ───────────────────────────────────────────

    def _drain_newline_delimited(self):
        while True:
            nl_idx = self._buffer.find(b"\n")
            if nl_idx == -1:
                if len(self._buffer) > _MAX_MESSAGE_BYTES:
                    raise FramingError("Newline-delimited message exceeds max size")
                return
            raw = bytes(self._buffer[:nl_idx])
            del self._buffer[:nl_idx + 1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            if raw:
                yield raw.decode("utf-8", errors="replace")

    def reset(self) -> None:
        """Clear buffered state, e.g. after a FramingError, before
        deciding whether to keep the connection alive."""
        self._buffer.clear()
        self._mode = None