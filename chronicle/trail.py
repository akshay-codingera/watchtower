"""
chronicle/trail.py
====================
WATCHTOWER — Audit Trail Query Interface

Read-side companion to auditor.py. Provides the filtering, pagination,
and grouping the portal's audit.html page needs, built entirely on top
of Archivist.fetch_audit_trail() — chronicle never opens its own
connection to SQLite (see ledger/__init__.py: ledger owns all SQL).

Archivist.fetch_audit_trail() currently only supports an `actor` filter
plus a row limit. Trail applies any additional filtering (action,
result, date range, keyword) in Python after that fetch. For a small
to mid-size audit trail (thousands to low tens-of-thousands of rows —
which is what one WATCHTOWER deployment produces) this is fine and
keeps chronicle self-contained. If a deployment's audit_trail table
grows large enough for this to matter, push the extra filters down
into Archivist.fetch_audit_trail()'s SQL instead of scaling this up.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from typing import Optional

from ledger.archivist import Archivist

logger = logging.getLogger(__name__)

# Upper bound on how many raw rows we'll pull from Archivist before
# applying Python-side filters — keeps a single trail() call bounded.
_MAX_FETCH = 5000


@dataclass
class TrailFilter:
    """
    Filter specification for audit trail queries.

    All fields optional. Mirrors the shape of ledger.archivist.LogFilter
    so the portal API layer can treat both consistently.
    """
    actor:      Optional[str] = None
    action:     Optional[str] = None    # exact match against action string
    result:     Optional[str] = None    # 'success' | 'failure'
    keyword:    Optional[str] = None    # substring match across target/detail
    from_time:  Optional[str] = None    # ISO datetime string, inclusive
    to_time:    Optional[str] = None    # ISO datetime string, inclusive
    limit:      int = 100
    offset:     int = 0

    def validate(self) -> None:
        if self.limit < 1 or self.limit > 5000:
            raise ValueError(f"limit must be 1-5000, got {self.limit}")
        if self.offset < 0:
            raise ValueError(f"offset must be >= 0, got {self.offset}")
        if self.result and self.result not in ("success", "failure"):
            raise ValueError("result must be 'success' or 'failure'")


class Trail:
    """
    Filtered, paginated view over the audit_trail table.

    Args:
        archivist: Archivist instance for the underlying read.
    """

    def __init__(self, archivist: Archivist) -> None:
        self._archivist = archivist

    def query(self, trail_filter: TrailFilter) -> list[dict]:
        """
        Fetch audit trail entries matching the filter.

        Args:
            trail_filter: TrailFilter specifying constraints.

        Returns:
            List of audit trail dicts, newest first, paginated.
        """
        trail_filter.validate()

        # Archivist can push actor + a raw limit down to SQL; everything
        # else is applied here. Over-fetch when other filters are set so
        # pagination on the filtered result stays accurate.
        fetch_limit = _MAX_FETCH if self._has_extra_filters(trail_filter) else (
            trail_filter.limit + trail_filter.offset
        )
        rows = self._archivist.fetch_audit_trail(limit=fetch_limit, actor=trail_filter.actor)

        rows = self._apply_filters(rows, trail_filter)

        return rows[trail_filter.offset: trail_filter.offset + trail_filter.limit]

    def count(self, trail_filter: TrailFilter) -> int:
        """Count entries matching the filter (for pagination UI)."""
        unpaginated = TrailFilter(
            actor=trail_filter.actor, action=trail_filter.action,
            result=trail_filter.result, keyword=trail_filter.keyword,
            from_time=trail_filter.from_time, to_time=trail_filter.to_time,
            limit=_MAX_FETCH, offset=0,
        )
        rows = self._archivist.fetch_audit_trail(limit=_MAX_FETCH, actor=unpaginated.actor)
        return len(self._apply_filters(rows, unpaginated))

    def recent_failures(self, hours: int = 24, limit: int = 50) -> list[dict]:
        """Convenience: recent failed actions (failed logins, denied permissions, etc.)."""
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        f = TrailFilter(result="failure", from_time=cutoff, limit=limit)
        return self.query(f)

    def actor_activity(self, actor: str, days: int = 30) -> list[dict]:
        """Convenience: everything a specific actor has done in the last N days."""
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        f = TrailFilter(actor=actor, from_time=cutoff, limit=1000)
        return self.query(f)

    def action_breakdown(self, hours: int = 24) -> dict[str, int]:
        """
        Count entries grouped by action string over the last N hours.
        Useful for an audit summary card on the dashboard.
        """
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        rows = self.query(TrailFilter(from_time=cutoff, limit=_MAX_FETCH))
        breakdown: dict[str, int] = {}
        for row in rows:
            action = row.get("action", "unknown")
            breakdown[action] = breakdown.get(action, 0) + 1
        return breakdown

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _has_extra_filters(f: TrailFilter) -> bool:
        return any([f.action, f.result, f.keyword, f.from_time, f.to_time])

    @staticmethod
    def _apply_filters(rows: list[dict], f: TrailFilter) -> list[dict]:
        result = rows

        if f.action:
            result = [r for r in result if r.get("action") == f.action]

        if f.result:
            result = [r for r in result if r.get("result") == f.result]

        if f.keyword:
            kw = f.keyword.lower()
            result = [
                r for r in result
                if kw in (r.get("target") or "").lower()
                or kw in (r.get("detail") or "").lower()
            ]

        if f.from_time:
            result = [r for r in result if (r.get("timestamp") or "") >= f.from_time]

        if f.to_time:
            result = [r for r in result if (r.get("timestamp") or "") <= f.to_time]

        return result