"""HTML page routes for the Watchtower portal.

Every view is a thin controller: it validates input, delegates to a
backend service, and renders a Jinja2 template. No business logic lives
here.
"""

from __future__ import annotations

import logging
from typing import Final

from flask import (
    Blueprint,
    abort,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from nucleus.config import cfg as _cfg
from sentinel_gate import auth as _auth  # type: ignore[import-not-found]
from nucleus.exceptions import SessionExpired, SessionInvalid  # type: ignore[import-not-found]

from portal import runtime as _rt
from portal.middleware import login_required, role_required

_ADMIN_USERNAME: Final[str] = "admin"

_LOG: Final = logging.getLogger(__name__)

bp = Blueprint("views", __name__)

_SESSION_COOKIE_KEY: Final[str] = "sid"


# ---------------------------------------------------------------------------
# Auth pages
# ---------------------------------------------------------------------------
@bp.get("/")
def index() -> object:
    """Root: dashboard when authenticated, gate otherwise."""
    if getattr(g, "principal", None) is None:
        return redirect(url_for("views.gate"))
    return redirect(url_for("views.observatory"))


@bp.get("/gate")
def gate() -> str:
    """Render the login page."""
    return render_template("gate.html", page_id="gate")


@bp.post("/gate")
def gate_submit() -> object:
    """Process login form submission via ``sentinel_gate.auth``."""
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    remote_ip = request.remote_addr or "unknown"

    if not username or not password:
        return render_template(
            "gate.html", page_id="gate", error="Username and password are required."
        ), 400

    if _rt.lockout.is_locked(remote_ip):
        _LOG.warning("login blocked (locked out) user=%s ip=%s", username, remote_ip)
        return render_template(
            "gate.html", page_id="gate", error="Account temporarily locked."
        ), 429

    # WATCHTOWER has a single admin account (see sentinel_gate/auth.py).
    ok = (
        username == _ADMIN_USERNAME
        and _auth.verify_password(password, _cfg.auth.admin_password_hash)
    )

    if not ok:
        _rt.lockout.record_failure(remote_ip)
        _rt.auditor.login_failed(actor=username, ip_address=remote_ip,
                                  user_agent=request.headers.get("User-Agent", ""),
                                  reason="invalid credentials")
        return render_template(
            "gate.html", page_id="gate", error="Invalid credentials."
        ), 401

    _rt.lockout.record_success(remote_ip)
    user_agent = request.headers.get("User-Agent", "")
    sid = _rt.sessions.create_session(
        username=username, role="admin", ip_address=remote_ip, user_agent=user_agent
    )
    session[_SESSION_COOKIE_KEY] = sid
    _rt.auditor.login_success(actor=username, ip_address=remote_ip,
                               user_agent=user_agent, session_id=sid[:16])
    return redirect(url_for("views.observatory"))


@bp.post("/logout")
@login_required
def logout() -> object:
    """Terminate the current session."""
    sid = session.pop(_SESSION_COOKIE_KEY, None)
    if sid:
        _rt.sessions.invalidate_session(sid)
    _rt.auditor.logout(
        actor=getattr(g.principal, "username", "unknown"),
        session_id=(sid or "")[:16],
        ip_address=request.remote_addr or "unknown",
    )
    return redirect(url_for("views.gate"))


# ---------------------------------------------------------------------------
# Application pages
# ---------------------------------------------------------------------------
@bp.get("/livefeed")
@login_required
def livefeed() -> str:
    return render_template("livefeed.html", page_id="livefeed")


@bp.get("/chronicle")
@login_required
def chronicle() -> str:
    return render_template("chronicle.html", page_id="chronicle")


@bp.get("/registry")
@login_required
def registry() -> str:
    return render_template("registry.html", page_id="registry")


@bp.get("/watchdog")
@login_required
def watchdog() -> str:
    return render_template("watchdog.html", page_id="watchdog")


@bp.get("/observatory")
@login_required
def observatory() -> str:
    return render_template("observatory.html", page_id="observatory")


@bp.get("/manifest")
@login_required
def manifest() -> str:
    return render_template("manifest.html", page_id="manifest")


@bp.get("/topology")
@login_required
def topology() -> str:
    return render_template("topology.html", page_id="topology")


@bp.get("/audit")
@login_required
@role_required("admin", "auditor")
def audit() -> str:
    return render_template("audit.html", page_id="audit")


@bp.get("/sessions")
@login_required
@role_required("admin")
def sessions_page() -> str:
    from chronicle.trail import TrailFilter
    history = _rt.trail.query(TrailFilter(action="login_success", limit=200))
    return render_template("sessions.html", page_id="sessions", history=history)


@bp.get("/health")
@login_required
def health() -> str:
    return render_template("health.html", page_id="health")


@bp.get("/forge")
@login_required
@role_required("admin")
def forge() -> str:
    return render_template("forge.html", page_id="forge")


@bp.get("/codex")
def codex() -> str:
    return render_template("codex.html", page_id="codex")


__all__ = ["bp"]
