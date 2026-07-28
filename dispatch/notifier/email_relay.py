"""
dispatch/notifier/email_relay.py
===================================
WATCHTOWER — Email Notification Channel

Sends alert notifications via SMTP using Python's stdlib smtplib —
no external dependency. Configuration comes entirely from
cfg.notifications (see nucleus/config.py's _NotificationConfig).

Design principle: connects fresh per notify() call rather than holding
a persistent SMTP connection. Alert volume is low enough (these are
already-correlated, cooldown-gated events, not raw log volume) that
connection reuse isn't worth the complexity of managing a stale/dead
persistent connection across arbitrary gaps between alerts.
"""

from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText

from nucleus.record import AlertRecord
from nucleus.exceptions import NotificationError
from dispatch.notifier import Notifier
from dispatch.rulebook import AlertRule

logger = logging.getLogger(__name__)


class EmailNotifier(Notifier):
    """
    SMTP email notifier.

    Args:
        smtp_host, smtp_port, smtp_user, smtp_password: SMTP server config.
        recipients:  List of recipient email addresses.
        from_addr:   From address. Defaults to smtp_user if not given.
        use_tls:     Whether to upgrade the connection with STARTTLS
                     (default True — plain SMTP should be rare).
        timeout:     Connection timeout in seconds.
    """

    channel_name = "email"

    def __init__(
        self, smtp_host: str, smtp_port: int, smtp_user: str, smtp_password: str,
        recipients: list[str], from_addr: str = "", use_tls: bool = True, timeout: int = 10,
    ) -> None:
        self._host        = smtp_host
        self._port        = smtp_port
        self._user        = smtp_user
        self._password    = smtp_password
        self._recipients  = recipients
        self._from_addr   = from_addr or smtp_user
        self._use_tls     = use_tls
        self._timeout     = timeout

    def notify(self, alert: AlertRecord, rule: AlertRule) -> None:
        """
        Send the alert as a plain-text email to every configured recipient.

        Raises:
            NotificationError: If the connection, auth, or send fails,
                               or if no recipients/host are configured.
        """
        if not self._host:
            raise NotificationError("email", "smtp_host is not configured")
        if not self._recipients:
            raise NotificationError("email", "no alert_recipients configured")

        message = MIMEText(self.format_message(alert, rule))
        message["Subject"] = f"WATCHTOWER [{alert.level.upper()}] {rule.name}"
        message["From"]    = self._from_addr
        message["To"]      = ", ".join(self._recipients)

        try:
            with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as server:
                if self._use_tls:
                    server.starttls()
                if self._user:
                    server.login(self._user, self._password)
                server.sendmail(self._from_addr, self._recipients, message.as_string())
        except (smtplib.SMTPException, OSError) as exc:
            raise NotificationError("email", str(exc)) from exc

        logger.info("Email alert sent to %d recipient(s): %s", len(self._recipients), rule.name)