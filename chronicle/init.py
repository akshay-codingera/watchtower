"""
chronicle/
==========
WATCHTOWER audit and compliance layer.

Chronicle owns the vocabulary and query surface for "who did what,
when" — everything downstream of ledger's raw audit_trail table.
Like beacon/, chronicle never opens its own SQLite connection; every
read goes through ledger.archivist.Archivist, every write goes through
ledger.scribe.Scribe.

Public interface:
    from chronicle.auditor    import Auditor
    from chronicle.trail      import Trail, TrailFilter
    from chronicle.compliance import ComplianceGenerator, ComplianceReport

Typical wiring in core.py:
    vault     = Vault(cfg.ledger.db_path)
    scribe    = Scribe(vault)
    archivist = Archivist(vault)

    auditor    = Auditor(scribe)
    trail      = Trail(archivist)
    compliance = ComplianceGenerator(archivist, trail)

Usage:
    # anywhere an admin action happens (sentinel_gate, portal/api):
    auditor.login_success(actor="akshay", ip_address=req.ip,
                           user_agent=req.ua, session_id=session.token)

    # portal/api/audit.py:
    rows = trail.query(TrailFilter(actor="akshay", limit=50))

    # scheduler/jobs/report.py, monthly:
    report = compliance.generate(period_days=30)
    compliance.to_pdf(report, "reports/2026-07-compliance.pdf")
"""

from chronicle.auditor    import Auditor
from chronicle.trail      import Trail, TrailFilter
from chronicle.compliance import ComplianceGenerator, ComplianceReport, ComplianceError

__all__ = [
    "Auditor",
    "Trail",
    "TrailFilter",
    "ComplianceGenerator",
    "ComplianceReport",
    "ComplianceError",
]