"""
dispatch/notifier/
====================
WATCHTOWER — Notification Channels

Every channel (browser SSE, email, webhook, Telegram) implements the
same tiny Notifier interface: one method, notify(alert, rule), that
either succeeds or raises NotificationError. incident.py never talks
to smtplib/urllib directly — it goes through NotifierRegistry.dispatch()
with the channel names from the rule's action_json.

Design principle: one channel failing must never block another. If a
rule's action list is ["email", "telegram"] and the SMTP server is
down, Telegram should still get the notification, and incident.py
should still know the email side failed (for retry/alerting-on-the-
alerting-system purposes). NotifierRegistry.dispatch() returns a
per-channel result dict rather than raising the first exception it hits.
"""

from __future__ import annotations

import abc
import logging

from nucleus.record import AlertRecord
from nucleus.exceptions import NotificationError
from nucleus.telemetry import metrics
from dispatch.rulebook import AlertRule

logger = logging.getLogger(__name__)


class Notifier(abc.ABC):
    """Base interface every notification channel implements."""

    #: Channel name as used in action_json's "notify" list (e.g. "email").
    channel_name: str = "base"

    @abc.abstractmethod
    def notify(self, alert: AlertRecord, rule: AlertRule) -> None:
        """
        Deliver a notification for a fired alert.

        Args:
            alert: The AlertRecord that was just written to alert_history.
            rule:  The AlertRule that fired it (for description/context).

        Raises:
            NotificationError: If delivery fails for any reason.
        """
        raise NotImplementedError

    def format_message(self, alert: AlertRecord, rule: AlertRule) -> str:
        """Shared plain-text message format — channels can override for richer formatting."""
        return (
            f"[{alert.level.upper()}] {rule.name}\n"
            f"{alert.reason}\n"
            f"Device: {alert.device_ip or 'n/a'}\n"
            f"Fired: {alert.fired_at or 'just now'}"
        )


class NotifierRegistry:
    """
    Holds configured notifier instances and dispatches to a subset by
    channel name.

    Args:
        notifiers: Dict mapping channel name -> Notifier instance.
                   Build this once at startup from whichever channels
                   are enabled in cfg.notifications.
    """

    def __init__(self, notifiers: dict[str, Notifier] | None = None) -> None:
        self._notifiers = notifiers or {}

    def register(self, notifier: Notifier) -> None:
        self._notifiers[notifier.channel_name] = notifier

    def dispatch(self, channels: list[str], alert: AlertRecord, rule: AlertRule) -> dict[str, bool]:
        """
        Attempt delivery on every requested channel independently.

        Args:
            channels: Channel names from the rule's action_json "notify" list.
            alert:    The fired AlertRecord.
            rule:     The AlertRule that fired.

        Returns:
            Dict mapping channel name -> True (delivered) / False (failed
            or not configured). Never raises — check the return value.
        """
        results: dict[str, bool] = {}
        for channel in channels:
            notifier = self._notifiers.get(channel)
            if not notifier:
                logger.warning("Notify channel '%s' requested but not configured — skipping", channel)
                results[channel] = False
                continue
            try:
                notifier.notify(alert, rule)
                results[channel] = True
                metrics.dispatch_notify_ok.increment()
            except NotificationError as exc:
                logger.error("Notification failed on channel '%s': %s", channel, exc)
                results[channel] = False
                metrics.dispatch_notify_errors.increment()
            except Exception as exc:
                # A notifier must never take down the alert pipeline —
                # catch anything unexpected too, not just NotificationError.
                logger.error("Unexpected error in '%s' notifier: %s", channel, exc)
                results[channel] = False
                metrics.dispatch_notify_errors.increment()
        return results