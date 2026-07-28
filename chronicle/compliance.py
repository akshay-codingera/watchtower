"""
chronicle/compliance.py
=========================
WATCHTOWER — Compliance Report Generation

Assembles a point-in-time compliance snapshot — log volume, audit
activity, unresolved alerts, and device coverage — and exports it as
CSV, JSON, or PDF for handoff to an auditor.

Design principle: report generation is read-only and touches nothing
but Archivist (chronicle's own Trail included). It never writes to the
database. All three export formats are built from the same
ComplianceReport dataclass so CSV/JSON/PDF can never silently diverge
from each other.

PDF export uses fpdf2 if it's installed (`pip install fpdf2`), and
raises a clear ComplianceError telling you how to install it if not —
it's a lazy import so CSV/JSON export works with zero extra
dependencies even on a box where fpdf2 was never installed.
"""

from __future__ import annotations

import csv
import datetime
import io
import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path

from nucleus.exceptions import WatchtowerError
from ledger.archivist import Archivist
from chronicle.trail import Trail, TrailFilter

logger = logging.getLogger(__name__)


class ComplianceError(WatchtowerError):
    """Raised when a compliance report cannot be generated or exported."""


@dataclass
class ComplianceReport:
    """
    A single point-in-time compliance snapshot.
    Every export format (CSV/JSON/PDF) is built from this same object.
    """
    generated_at:      str = ""
    period_days:        int = 30
    log_totals:          dict = field(default_factory=dict)   # category -> count
    log_summary:         dict = field(default_factory=dict)   # total/critical/errors/warnings/sources
    device_coverage:     dict = field(default_factory=dict)   # total/online/silent/offline/unknown
    unresolved_alerts:   int  = 0
    alerts_by_level:     dict = field(default_factory=dict)
    audit_action_totals: dict = field(default_factory=dict)
    audit_failures:      int  = 0
    audit_failure_sample: list = field(default_factory=list)  # up to 20 recent failures

    def to_dict(self) -> dict:
        return asdict(self)


class ComplianceGenerator:
    """
    Builds ComplianceReport objects and exports them.

    Args:
        archivist: Archivist instance for log/device/alert queries.
        trail:     Trail instance for audit queries.
    """

    def __init__(self, archivist: Archivist, trail: Trail) -> None:
        self._archivist = archivist
        self._trail     = trail

    def generate(self, period_days: int = 30) -> ComplianceReport:
        """
        Build a compliance snapshot covering the last `period_days`.

        Args:
            period_days: Look-back window in days for time-bounded
                         sections (audit activity, failures). Log and
                         device totals are current-state, not windowed.

        Returns:
            A populated ComplianceReport.
        """
        report = ComplianceReport(
            generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            period_days  = period_days,
        )

        report.log_totals   = self._archivist.stats_category_totals()
        report.log_summary  = self._archivist.stats_summary(hours=period_days * 24)

        devices = self._archivist.fetch_devices()
        coverage = {"total": len(devices), "online": 0, "silent": 0, "offline": 0, "unknown": 0}
        for d in devices:
            status = d.get("status", "unknown")
            coverage[status] = coverage.get(status, 0) + 1
        report.device_coverage = coverage

        alerts = self._archivist.fetch_alerts(acknowledged=False, limit=5000)
        report.unresolved_alerts = len(alerts)
        by_level: dict = {}
        for a in alerts:
            level = a.get("level", "unknown")
            by_level[level] = by_level.get(level, 0) + 1
        report.alerts_by_level = by_level

        report.audit_action_totals = self._trail.action_breakdown(hours=period_days * 24)
        failures = self._trail.recent_failures(hours=period_days * 24, limit=1000)
        report.audit_failures = len(failures)
        report.audit_failure_sample = failures[:20]

        logger.info(
            "Compliance report generated: %d-day window, %d unresolved alerts, %d audit failures",
            period_days, report.unresolved_alerts, report.audit_failures
        )
        return report

    # ── Exporters ──────────────────────────────────────────────────────────────

    def to_json(self, report: ComplianceReport, path: str | Path | None = None) -> str:
        """
        Serialize a report to JSON.

        Args:
            report: A generated ComplianceReport.
            path:   Optional filesystem path to also write the JSON to.

        Returns:
            The JSON string.
        """
        payload = json.dumps(report.to_dict(), indent=2, default=str)
        if path:
            Path(path).write_text(payload, encoding="utf-8")
        return payload

    def to_csv(self, report: ComplianceReport, path: str | Path | None = None) -> str:
        """
        Flatten a report into a CSV of section/metric/value rows —
        auditors generally want a flat sheet, not nested JSON.

        Args:
            report: A generated ComplianceReport.
            path:   Optional filesystem path to also write the CSV to.

        Returns:
            The CSV string.
        """
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["section", "metric", "value"])

        writer.writerow(["meta", "generated_at", report.generated_at])
        writer.writerow(["meta", "period_days", report.period_days])

        for category, count in report.log_totals.items():
            writer.writerow(["log_totals", category, count])

        for metric, value in report.log_summary.items():
            writer.writerow(["log_summary", metric, value])

        for status, count in report.device_coverage.items():
            writer.writerow(["device_coverage", status, count])

        writer.writerow(["alerts", "unresolved_total", report.unresolved_alerts])
        for level, count in report.alerts_by_level.items():
            writer.writerow(["alerts_by_level", level, count])

        for action, count in report.audit_action_totals.items():
            writer.writerow(["audit_actions", action, count])

        writer.writerow(["audit", "failure_count", report.audit_failures])

        payload = buffer.getvalue()
        if path:
            Path(path).write_text(payload, encoding="utf-8")
        return payload

    def to_pdf(self, report: ComplianceReport, path: str | Path) -> Path:
        """
        Render a report as a simple one-page PDF summary.

        Requires fpdf2 (`pip install fpdf2 --break-system-packages`).
        Lazily imported so CSV/JSON export works without it installed.

        Args:
            report: A generated ComplianceReport.
            path:   Filesystem path to write the PDF to.

        Returns:
            The Path the PDF was written to.

        Raises:
            ComplianceError: If fpdf2 is not installed.
        """
        try:
            from fpdf import FPDF
        except ImportError as exc:
            raise ComplianceError(
                "PDF export requires fpdf2. Install with: "
                "pip install fpdf2 --break-system-packages"
            ) from exc

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "WATCHTOWER Compliance Report", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Generated: {report.generated_at}  |  Period: {report.period_days} days", ln=True)
        pdf.ln(4)

        self._pdf_section(pdf, "Log Totals", report.log_totals)
        self._pdf_section(pdf, "Log Summary", report.log_summary)
        self._pdf_section(pdf, "Device Coverage", report.device_coverage)
        self._pdf_section(pdf, "Alerts by Level", report.alerts_by_level)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, f"Unresolved alerts: {report.unresolved_alerts}", ln=True)
        self._pdf_section(pdf, "Audit Actions (period)", report.audit_action_totals)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, f"Audit failures (period): {report.audit_failures}", ln=True)

        out_path = Path(path)
        pdf.output(str(out_path))
        logger.info("Compliance PDF written to %s", out_path)
        return out_path

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _pdf_section(pdf, title: str, data: dict) -> None:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, title, ln=True)
        pdf.set_font("Helvetica", "", 10)
        if not data:
            pdf.cell(0, 6, "  (no data)", ln=True)
        for key, value in data.items():
            pdf.cell(0, 6, f"  {key}: {value}", ln=True)
        pdf.ln(2)