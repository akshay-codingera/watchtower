"""Watchtower portal application factory.

``create_app`` produces a fully-wired Flask instance ready to be served
by ``core.py``. No global application object is created at import time.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Final, Optional

from flask import Flask

from nucleus.config import config as _config  # type: ignore[import-not-found]

from portal.errors import register_error_handlers
from portal.middleware import register_middleware
from portal.security import register_security
from portal.stream import bp as stream_bp
from portal.stream import install_shutdown_flag, trip_shutdown
from portal.views import bp as views_bp

_LOG: Final = logging.getLogger(__name__)

_PORTAL_SECTION: Final[str] = "portal"


def _cfg_get(section: str, option: str, default: Optional[str] = None) -> Optional[str]:
    if _config.has_option(section, option):
        return _config.get(section, option)
    return default


def _cfg_getint(section: str, option: str, default: int) -> int:
    if _config.has_option(section, option):
        return _config.getint(section, option)
    return default


def _cfg_getbool(section: str, option: str, default: bool) -> bool:
    if _config.has_option(section, option):
        return _config.getboolean(section, option)
    return default


def _apply_configuration(app: Flask) -> None:
    """Copy relevant options from ``nucleus.config`` onto the Flask app."""
    secret = _cfg_get(_PORTAL_SECTION, "secret_key")
    if not secret:
        raise RuntimeError(
            "portal.secret_key is not configured in Watchtower config.ini"
        )
    app.config["SECRET_KEY"] = secret
    app.config["PORTAL_HTTPS"] = _cfg_getbool(_PORTAL_SECTION, "https", False)
    app.config["MAX_CONTENT_LENGTH"] = _cfg_getint(
        _PORTAL_SECTION, "max_content_length", 4 * 1024 * 1024
    )
    app.config["JSON_SORT_KEYS"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = False
    app.config["SESSION_COOKIE_NAME"] = _cfg_get(
        _PORTAL_SECTION, "session_cookie_name", "watchtower_session"
    )
    app.config["PERMANENT_SESSION_LIFETIME"] = _cfg_getint(
        _PORTAL_SECTION, "session_lifetime_seconds", 8 * 60 * 60
    )
    csp = _cfg_get(_PORTAL_SECTION, "content_security_policy")
    if csp:
        app.config["CONTENT_SECURITY_POLICY"] = csp


def _register_blueprints(app: Flask) -> None:
    from portal.api.control import bp as control_bp
    from portal.api.ingest import bp as ingest_bp
    from portal.api.logfeed import bp as logfeed_bp
    from portal.api.registry import bp as registry_bp
    from portal.api.swagger import bp as swagger_bp
    from portal.api.webhooks import bp as webhooks_bp

    app.register_blueprint(views_bp)
    app.register_blueprint(stream_bp)
    app.register_blueprint(logfeed_bp)
    app.register_blueprint(registry_bp)
    app.register_blueprint(control_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(webhooks_bp)
    app.register_blueprint(swagger_bp)


def create_app(overrides: Optional[dict[str, Any]] = None) -> Flask:
    """Build and return the Watchtower portal Flask application.

    Args:
        overrides: Optional mapping merged into ``app.config`` last so
            tests and embedded runners can adjust behaviour.

    Returns:
        Configured :class:`flask.Flask` instance.
    """
    package_root = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(package_root / "templates"),
        static_folder=str(package_root / "static"),
        static_url_path="/static",
    )

    _apply_configuration(app)
    if overrides:
        app.config.update(overrides)

    install_shutdown_flag(app)
    register_security(app)
    register_middleware(app)
    _register_blueprints(app)
    register_error_handlers(app)

    @app.teardown_appcontext
    def _cleanup(_exc: BaseException | None) -> None:
        # Reserved for future per-request resource cleanup.
        return None

    _LOG.info("portal ready (debug=%s)", app.debug)
    return app


def shutdown(app: Flask) -> None:
    """Signal SSE streams and other long-lived resources to stop."""
    trip_shutdown(app)


__all__ = ["create_app", "shutdown"]
