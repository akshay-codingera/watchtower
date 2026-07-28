"""
dispatch/notifier/webhook.py
==============================
WATCHTOWER — Webhook Notification Channel

POSTs a JSON payload to a configured URL. Uses stdlib urllib rather
than requests — this is the only network call this notifier makes,
not worth a dependency for.

Payload shape is deliberately simple and stable — treat it as a
mini-API contract. If you need to change field names, add new fields
rather than renaming/removing old ones, so existing webhook consumers
(Slack relay, PagerDuty bridge, whatever's on the other end) don't
silently break.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from nucleus.record import AlertRecord
from nucleus.exceptions import NotificationError
from dispatch.notifier import Notifier
from dispatch.rulebook import AlertRule

logger = logging.getLogger(__name__)


class WebhookNotifier(Notifier):
    """
    Generic JSON webhook notifier.

    Args:
        url:     Target URL to POST to.
        timeout: Request timeout in seconds.
    """

    channel_name = "webhook"

    def __init__(self, url: str, timeout: int = 10) -> None:
        self._url = url
        self._timeout = timeout

    def notify(self, alert: AlertRecord, rule: AlertRule) -> None:
        """
        POST a JSON payload describing the alert.

        Payload:
            {
                "source":    "watchtower",
                "level":     alert.level,
                "rule_name": rule.name,
                "reason":    alert.reason,
                "device_ip": alert.device_ip,
                "fired_at":  alert.fired_at,
                "message":   <formatted plain-text summary>
            }

        Raises:
            NotificationError: If the URL isn't configured, or the
                               request fails / returns a non-2xx status.
        """
        if not self._url:
            raise NotificationError("webhook", "webhook_url is not configured")

        payload = json.dumps({
            "source":    "watchtower",
            "level":     alert.level,
            "rule_name": rule.name,
            "reason":    alert.reason,
            "device_ip": alert.device_ip,
            "fired_at":  alert.fired_at,
            "message":   self.format_message(alert, rule),
        }).encode("utf-8")

        request = urllib.request.Request(
            self._url, data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                if response.status >= 300:
                    raise NotificationError("webhook", f"HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            raise NotificationError("webhook", f"HTTP {exc.code}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise NotificationError("webhook", str(exc.reason)) from exc
        except OSError as exc:
            raise NotificationError("webhook", str(exc)) from exc

        logger.info("Webhook alert delivered: %s", rule.name)