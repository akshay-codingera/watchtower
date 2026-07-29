"""
pipeline/forge/
================
WATCHTOWER — Format Parsers

Every concrete parser in this package turns a raw syslog message into
populated LogRecord fields for one specific wire format. sieve.py
picks which parser handles a given record; marshal.py is the only
caller of either.

Every parser implements the same tiny interface: one method,
parse(record), that mutates and returns the LogRecord in place, or
raises ParseError (nucleus.exceptions) if the message doesn't actually
match the format it claims to. marshal.py catches ParseError and falls
back to forge.plaintext.PlaintextParser, which never raises.

Design principle: parsers are stateless and safe to share a single
instance across every ingest worker thread — no parser method should
ever hold a lock or touch the network/filesystem.
"""

from __future__ import annotations

import abc

from nucleus.record import LogRecord


class ForgeParser(abc.ABC):
    """Base interface every format-specific parser implements."""

    #: LogFormat value this parser claims to handle (see nucleus.constants.LogFormat).
    format_name: str = "unknown"

    @abc.abstractmethod
    def parse(self, record: LogRecord) -> LogRecord:
        """
        Parse `record.raw_message` and populate fields on `record` in place.

        Args:
            record: A LogRecord already carrying raw_message/sender_ip/
                    sender_port/transport/received_at from intake.

        Returns:
            The same LogRecord instance, for chaining.

        Raises:
            ParseError: If raw_message does not actually match this
                        parser's format.
        """
        raise NotImplementedError


__all__ = ["ForgeParser"]
