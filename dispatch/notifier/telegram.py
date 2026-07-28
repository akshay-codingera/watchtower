"""
dispatch/notifier/telegram.py
================================
WATCHTOWER — Telegram Notification Channel

Sends alerts via the Telegram Bot API's sendMessage endpoint. Uses
stdlib urllib — same reasoning as webhook.py, this is one HTTPS POST,
not worth a python-telegram-bot dependency.

Setup (for the notes/docs, since you'll need this once):
    1. Message @BotFather on Telegram, /newbot, get a bot token.
    2. Add the bot to the chat/channel you want alerts in.
    3. Get the chat_id (e.g. via https://api.telegram.org/bot<token>/getUpdates
       after sending the bot a message).
    4. Set telegram_token / telegram_chat_id in config.ini's [notifications].
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

_API_BASE = "https://api.telegram.org"


class TelegramNotifier(Notifier):
    """
    Telegram Bot API notifier.

    Args:
        bot_token: Telegram bot token from @BotFather.
        chat_id:   Destination chat/channel ID.
        timeout:   Request timeout in seconds.
    """

    channel_name = "telegram"

    def __init__(self, bot_token: str, chat_id: str, timeout: int = 10) -> None:
        self._token   = bot_token
        self._chat_id = chat_id
        self._timeout = timeout

    def notify(self, alert: AlertRecord, rule: AlertRule) -> None:
        """
        Send the alert as a Telegram message.

        Raises:
            NotificationError: If token/chat_id aren't configured, or
                               the API call fails / returns ok=false.
        """
        if not self._token or not self._chat_id:
            raise NotificationError("telegram", "telegram_token or telegram_chat_id not configured")

        # Telegram Markdown — escape sparingly, this is a controlled
        # message we compose ourselves, not user-supplied free text
        # beyond the log-derived reason string.
        text = f"*WATCHTOWER [{alert.level.upper()}]* {rule.name}\n{alert.reason}"
        if alert.device_ip:
            text += f"\nDevice: `{alert.device_ip}`"

        payload = json.dumps({
            "chat_id":    self._chat_id,
            "text":       text,
            "parse_mode": "Markdown",
        }).encode("utf-8")

        url = f"{_API_BASE}/bot{self._token}/sendMessage"
        request = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
                if not body.get("ok"):
                    raise NotificationError("telegram", body.get("description", "unknown error"))
        except urllib.error.HTTPError as exc:
            raise NotificationError("telegram", f"HTTP {exc.code}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise NotificationError("telegram", str(exc.reason)) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise NotificationError("telegram", str(exc)) from exc

        logger.info("Telegram alert delivered: %s", rule.name)