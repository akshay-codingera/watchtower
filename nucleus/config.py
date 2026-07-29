"""
nucleus/config.py
=================
WATCHTOWER — Enterprise Log Management & Network Monitoring Platform

Configuration loader, validator, and accessor.

Design principles:
- Single source of truth: config.ini is the only place settings live.
- Fail fast: missing or invalid config raises ConfigError at startup,
  not buried in a random function at runtime.
- Typed access: every getter returns the correct Python type,
  never a raw string.
- Singleton: the module-level `cfg` object is loaded once and imported
  everywhere. Never re-read the file on every access.
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Any

from nucleus.exceptions import ConfigError, ConfigKeyMissing, ConfigValueInvalid


# ── Config file location ──────────────────────────────────────────────────────
# Walk up from this file's location to find config.ini at project root.

def _find_config_file() -> Path:
    """Find config.ini by walking up from nucleus/ to the project root."""
    current = Path(__file__).parent
    for _ in range(4):                    # max 4 levels up
        candidate = current / "config.ini"
        if candidate.exists():
            return candidate
        current = current.parent
    # fallback: look in CWD (useful when running from project root)
    cwd_candidate = Path.cwd() / "config.ini"
    if cwd_candidate.exists():
        return cwd_candidate
    raise ConfigError(
        "config.ini not found. "
        "Run WATCHTOWER from the project root directory."
    )


# ── WatchtowerConfig class ────────────────────────────────────────────────────

class WatchtowerConfig:
    """
    Typed configuration accessor for the entire WATCHTOWER platform.

    Usage:
        from nucleus.config import cfg
        port = cfg.intake.udp_port          # returns int
        db   = cfg.ledger.db_path           # returns str
    """

    def __init__(self, path: Path | str | None = None):
        self._path   = Path(path) if path else _find_config_file()
        self._parser = configparser.ConfigParser(interpolation=None)

        if not self._path.exists():
            raise ConfigError(f"Config file not found: {self._path}")

        self._parser.read(self._path, encoding="utf-8")
        self._validate()

        # Expose section-level accessors as attributes
        self.server       = _ServerConfig(self._parser)
        self.intake       = _IntakeConfig(self._parser)
        self.ledger       = _LedgerConfig(self._parser)
        self.auth         = _AuthConfig(self._parser)
        self.relay        = _RelayConfig(self._parser)
        self.scheduler    = _SchedulerConfig(self._parser)
        self.notifications = _NotificationConfig(self._parser)
        self.beacon       = _BeaconConfig(self._parser)
        self.portal       = _PortalConfig(self._parser)

    @property
    def parser(self) -> configparser.ConfigParser:
        """Raw configparser, for modules that need arbitrary section/option access."""
        return self._parser

    def _validate(self) -> None:
        """Check that all required sections and keys exist."""
        required: dict[str, list[str]] = {
            "server":        ["name", "environment"],
            "intake":        ["udp_host", "udp_port", "tcp_port"],
            "ledger":        ["db_path"],
            "auth":          ["admin_password_hash", "secret_key"],
        }
        for section, keys in required.items():
            if not self._parser.has_section(section):
                raise ConfigError(
                    f"Missing required config section: [{section}]",
                    {"file": str(self._path)}
                )
            for key in keys:
                if not self._parser.has_option(section, key):
                    raise ConfigKeyMissing(
                        f"Missing required config key: [{section}] {key}",
                        {"section": section, "key": key}
                    )

    def reload(self) -> None:
        """Re-read config.ini from disk. Call on SIGHUP."""
        self._parser.read(self._path, encoding="utf-8")
        self._validate()

    def __repr__(self) -> str:
        return f"WatchtowerConfig(path={self._path})"


# ── Section-level config classes ──────────────────────────────────────────────

class _BaseConfig:
    """Helper base with typed getters."""

    def __init__(self, parser: configparser.ConfigParser, section: str):
        self._p = parser
        self._s = section

    def _str(self, key: str, fallback: str = "") -> str:
        return self._p.get(self._s, key, fallback=fallback).strip()

    def _int(self, key: str, fallback: int = 0) -> int:
        raw = self._p.get(self._s, key, fallback=str(fallback))
        try:
            return int(raw)
        except ValueError:
            raise ConfigValueInvalid(
                f"[{self._s}] {key} must be an integer, got: {raw!r}"
            )

    def _float(self, key: str, fallback: float = 0.0) -> float:
        raw = self._p.get(self._s, key, fallback=str(fallback))
        try:
            return float(raw)
        except ValueError:
            raise ConfigValueInvalid(
                f"[{self._s}] {key} must be a float, got: {raw!r}"
            )

    def _bool(self, key: str, fallback: bool = False) -> bool:
        raw = self._p.get(self._s, key, fallback=str(fallback)).lower()
        if raw in ("true", "yes", "1", "on"):
            return True
        if raw in ("false", "no", "0", "off"):
            return False
        raise ConfigValueInvalid(
            f"[{self._s}] {key} must be a boolean, got: {raw!r}"
        )

    def _list(self, key: str, fallback: str = "") -> list[str]:
        raw = self._p.get(self._s, key, fallback=fallback)
        return [item.strip() for item in raw.split(",") if item.strip()]


class _ServerConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "server")

    @property
    def name(self) -> str:        return self._str("name", "WATCHTOWER")
    @property
    def environment(self) -> str: return self._str("environment", "production")
    @property
    def debug(self) -> bool:      return self._bool("debug", False)
    @property
    def log_level(self) -> str:   return self._str("log_level", "INFO")


class _IntakeConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "intake")

    @property
    def udp_host(self) -> str:        return self._str("udp_host", "0.0.0.0")
    @property
    def udp_port(self) -> int:        return self._int("udp_port", 514)
    @property
    def tcp_port(self) -> int:        return self._int("tcp_port", 514)
    @property
    def tls_port(self) -> int:        return self._int("tls_port", 6514)
    @property
    def tls_enabled(self) -> bool:    return self._bool("tls_enabled", False)
    @property
    def tls_cert(self) -> str:        return self._str("tls_cert", "")
    @property
    def tls_key(self) -> str:         return self._str("tls_key", "")
    @property
    def queue_size(self) -> int:      return self._int("queue_size", 10000)
    @property
    def rate_limit(self) -> int:
        """Max messages per source IP per second. 0 = disabled."""
        return self._int("rate_limit", 1000)
    @property
    def recv_buffer(self) -> int:     return self._int("recv_buffer", 4194304)  # 4MB


class _LedgerConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "ledger")

    @property
    def db_path(self) -> str:
        return self._str("db_path", "logs/syslog.db")
    @property
    def retention_days(self) -> dict[str, int]:
        """Per-category retention in days."""
        return {
            "auth":     self._int("retention_auth_days",     90),
            "network":  self._int("retention_network_days",  60),
            "firewall": self._int("retention_firewall_days", 90),
            "system":   self._int("retention_system_days",   30),
            "app":      self._int("retention_app_days",      30),
        }
    @property
    def fts_enabled(self) -> bool:    return self._bool("fts_enabled", True)
    @property
    def wal_mode(self) -> bool:       return self._bool("wal_mode", True)


class _AuthConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "auth")

    @property
    def admin_password_hash(self) -> str:
        return self._str("admin_password_hash")
    @property
    def secret_key(self) -> str:
        return self._str("secret_key")
    @property
    def session_lifetime(self) -> int:
        return self._int("session_lifetime", 28800)   # 8 hours
    @property
    def max_failed_logins(self) -> int:
        return self._int("max_failed_logins", 5)
    @property
    def lockout_duration(self) -> int:
        return self._int("lockout_duration", 300)     # 5 minutes


class _RelayConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "relay")

    @property
    def enabled(self) -> bool:          return self._bool("enabled", False)
    @property
    def role(self) -> str:              return self._str("role", "standalone")  # primary/standby/standalone
    @property
    def peer_ip(self) -> str:           return self._str("peer_ip", "")
    @property
    def virtual_ip(self) -> str:        return self._str("virtual_ip", "")
    @property
    def gateway_ip(self) -> str:
        """
        Default gateway IP, used by consensus.py's self-isolation
        check. Must be an address that's reachable independently of
        the peer — pinging this confirms this node's own network is
        up before trusting a "peer unreachable" observation.
        """
        return self._str("gateway_ip", "")
    @property
    def heartbeat_interval(self) -> int: return self._int("heartbeat_interval", 1)
    @property
    def sync_interval(self) -> int:     return self._int("sync_interval", 5)


class _SchedulerConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "scheduler")

    @property
    def enabled(self) -> bool:          return self._bool("enabled", True)
    @property
    def backup_hour(self) -> int:       return self._int("backup_hour", 2)
    @property
    def retention_hour(self) -> int:    return self._int("retention_hour", 3)
    @property
    def digest_hour(self) -> int:       return self._int("digest_hour", 7)
    @property
    def snmp_poll_interval(self) -> int: return self._int("snmp_poll_interval", 300)


class _NotificationConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "notifications")

    @property
    def email_enabled(self) -> bool:    return self._bool("email_enabled", False)
    @property
    def smtp_host(self) -> str:         return self._str("smtp_host", "")
    @property
    def smtp_port(self) -> int:         return self._int("smtp_port", 587)
    @property
    def smtp_user(self) -> str:         return self._str("smtp_user", "")
    @property
    def smtp_password(self) -> str:     return self._str("smtp_password", "")
    @property
    def alert_recipients(self) -> list[str]: return self._list("alert_recipients")
    @property
    def telegram_enabled(self) -> bool: return self._bool("telegram_enabled", False)
    @property
    def telegram_token(self) -> str:    return self._str("telegram_token", "")
    @property
    def telegram_chat_id(self) -> str:  return self._str("telegram_chat_id", "")
    @property
    def webhook_enabled(self) -> bool:  return self._bool("webhook_enabled", False)
    @property
    def webhook_url(self) -> str:       return self._str("webhook_url", "")


class _BeaconConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "beacon")

    @property
    def ping_interval(self) -> int:      return self._int("ping_interval", 30)
    @property
    def ping_timeout(self) -> int:       return self._int("ping_timeout", 2)
    @property
    def offline_threshold(self) -> int:  return self._int("offline_threshold", 900)
    @property
    def silent_threshold(self) -> int:   return self._int("silent_threshold", 300)
    @property
    def arp_scan_enabled(self) -> bool:  return self._bool("arp_scan_enabled", False)
    @property
    def snmp_enabled(self) -> bool:      return self._bool("snmp_enabled", False)
    @property
    def snmp_community(self) -> str:     return self._str("snmp_community", "public")
    @property
    def subnet(self) -> str:             return self._str("subnet", "")

    # ── Standalone DHCP (lab/test networks only — see beacon/dhcpd.py) ────
    @property
    def dhcp_mode(self) -> str:
        """'disabled' (default) or 'standalone'. Never enable standalone
        on a network segment that already has a DHCP server."""
        return self._str("dhcp_mode", "disabled")
    @property
    def dhcp_interface(self) -> str:     return self._str("dhcp_interface", "")
    @property
    def dhcp_range_start(self) -> str:   return self._str("dhcp_range_start", "")
    @property
    def dhcp_range_end(self) -> str:     return self._str("dhcp_range_end", "")
    @property
    def dhcp_lease_time(self) -> str:    return self._str("dhcp_lease_time", "12h")
    @property
    def dhcp_option7(self) -> str:
        """The IP address devices will be told to send syslog to."""
        return self._str("dhcp_option7", "")
    @property
    def dhcp_gateway(self) -> str:       return self._str("dhcp_gateway", "")
    @property
    def dhcp_dns_servers(self) -> list[str]: return self._list("dhcp_dns_servers")


class _PortalConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "portal")

    @property
    def host(self) -> str:                return self._str("host", "0.0.0.0")
    @property
    def port(self) -> int:                return self._int("port", 5000)
    @property
    def https(self) -> bool:              return self._bool("https", False)
    @property
    def max_content_length(self) -> int:  return self._int("max_content_length", 4 * 1024 * 1024)
    @property
    def session_cookie_name(self) -> str: return self._str("session_cookie_name", "watchtower_session")
    @property
    def content_security_policy(self) -> str: return self._str("content_security_policy", "")


class _PortalConfig(_BaseConfig):
    def __init__(self, p): super().__init__(p, "portal")

    @property
    def host(self) -> str:                return self._str("host", "0.0.0.0")
    @property
    def port(self) -> int:                return self._int("port", 5000)
    @property
    def https(self) -> bool:              return self._bool("https", False)
    @property
    def max_content_length(self) -> int:  return self._int("max_content_length", 4 * 1024 * 1024)
    @property
    def session_cookie_name(self) -> str: return self._str("session_cookie_name", "watchtower_session")
    @property
    def content_security_policy(self) -> str: return self._str("content_security_policy", "")


# ── Module-level singleton ────────────────────────────────────────────────────
# Import this object everywhere. It is loaded once at first import.
# If config.ini is missing or invalid, this raises ConfigError at startup.

try:
    cfg = WatchtowerConfig()
except ConfigError:
    # config.ini not yet present (e.g. during testing or initial setup).
    # Tests should call WatchtowerConfig(path="path/to/test_config.ini")
    # and mock 'cfg' in nucleus.config.
    cfg = None   # type: ignore