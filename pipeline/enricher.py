"""
pipeline/enricher.py
======================
WATCHTOWER — Log Enrichment

Populates the enrichment fields nucleus.record.LogRecord reserves for
it — see the "Enrichment fields (populated by enricher.py)" block in
nucleus/record.py: geo_country/geo_city/geo_isp, is_threat/threat_score,
rdns.

Design principle: enrichment runs once per record on the ingest hot
path, so every check here is either free (pure Python, no I/O) or
skipped outright when it can't possibly help. No GeoIP database or
threat-intel feed ships with WATCHTOWER — requirements.txt is empty
and docs/deployment.md is explicit that the platform is stdlib-only
except for chronicle/compliance.py's optional fpdf2 — so this module
holds to the same principle rather than faking a lookup:

    - geo_* fields only get populated for the trivial "this is a
      private/reserved address, not routed on the public Internet"
      case (ipaddress.*.is_private, is_loopback, is_link_local) —
      genuinely resolving a public IP to a country/city needs a real
      GeoIP database this module deliberately does not bundle or fake.
    - is_threat/threat_score reflect one narrow, free-to-check signal:
      RFC 5737 / RFC 6598 documentation/shared-address ranges that
      should never appear as a real sender on a production network.
      Anything beyond that needs a real threat-intel feed, which is
      intentionally out of scope here — same "don't fake it" principle
      as the GeoIP case above.
    - rdns does one reverse DNS lookup via socket.gethostbyaddr(), and
      only for public addresses (private/loopback/link-local never
      usefully resolve) — this is the one enrichment step that makes a
      blocking network call, so it is wrapped tightly and can never
      raise or hang past the OS resolver's own timeout behavior.

Extending this to a real MaxMind GeoLite2 database or a real
threat-intel feed is a natural next step (the same "optional
dependency" pattern already used for chronicle/compliance.py's fpdf2)
— deliberately left as a follow-up rather than guessed at here.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Optional, Union

from nucleus.record import LogRecord

logger = logging.getLogger(__name__)

_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# RFC 5737 (TEST-NET-1/2/3) and RFC 6598 (shared address space) —
# addresses that should never legitimately appear as a real sender on
# a production network. A hit here is a much stronger signal than
# "public IP, unknown" and costs nothing to check.
_DOCUMENTATION_RANGES = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10")
)


class Enricher:
    """Best-effort, stdlib-only log enrichment (see module docstring)."""

    def enrich(self, record: LogRecord) -> LogRecord:
        """
        Populate geo_*/is_threat/threat_score/rdns on `record` in place.

        Never raises — every sub-step is independently guarded so a
        DNS hiccup or a malformed sender_ip can't take down ingest.
        """
        addr = self._parse_ip(record.sender_ip)
        if addr is None:
            return record

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            record.geo_country = "N/A"
            record.geo_city = "Private Network"
            return record

        if any(addr in net for net in _DOCUMENTATION_RANGES):
            record.is_threat = True
            record.threat_score = 100
            return record

        record.rdns = self._reverse_dns(record.sender_ip)
        return record

    @staticmethod
    def _parse_ip(value: str) -> Optional[_IPAddress]:
        if not value:
            return None
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    @staticmethod
    def _reverse_dns(ip: str) -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""


__all__ = ["Enricher"]
