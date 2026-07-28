"""
dispatch/
=========
WATCHTOWER alert and notification layer.

Pipeline: correlator.py watches every LogRecord against rules loaded
by rulebook.py; a threshold crossing produces a MatchEvent; incident.py
turns that into a persisted alert_history row and fans notifications
out through notifier/*. Only rulebook.py (rule CRUD) and incident.py
(alert writes/reads) touch the ledger — correlator.py and notifier/*
are pure logic / outbound network calls.

Public interface:
    from dispatch.rulebook    import RuleBook, AlertRule, AlertCondition, AlertAction
    from dispatch.correlator  import Correlator, MatchEvent
    from dispatch.incident    import IncidentManager
    from dispatch.notifier    import Notifier, NotifierRegistry
    from dispatch.notifier.browser     import BrowserNotifier
    from dispatch.notifier.email_relay import EmailNotifier
    from dispatch.notifier.webhook     import WebhookNotifier
    from dispatch.notifier.telegram    import TelegramNotifier

Typical wiring in core.py:
    vault     = Vault(cfg.ledger.db_path)
    scribe    = Scribe(vault)
    archivist = Archivist(vault)

    rulebook = RuleBook(scribe, archivist)
    rulebook.seed_builtins()             # once — no-op after first run

    notifiers = NotifierRegistry()
    notifiers.register(BrowserNotifier())
    if cfg.notifications.email_enabled:
        notifiers.register(EmailNotifier(
            cfg.notifications.smtp_host, cfg.notifications.smtp_port,
            cfg.notifications.smtp_user, cfg.notifications.smtp_password,
            cfg.notifications.alert_recipients,
        ))
    if cfg.notifications.telegram_enabled:
        notifiers.register(TelegramNotifier(
            cfg.notifications.telegram_token, cfg.notifications.telegram_chat_id,
        ))
    if cfg.notifications.webhook_enabled:
        notifiers.register(WebhookNotifier(cfg.notifications.webhook_url))

    correlator = Correlator(rulebook)
    incidents  = IncidentManager(scribe, archivist, notifiers)

    # Called per-message from the pipeline, after sentinel.py seals the record:
    for match in correlator.evaluate(record):
        incidents.open_from_match(match)

    # After any rule create/update/enable/disable via the portal API:
    correlator.reload_rules()
"""

from dispatch.rulebook   import RuleBook, AlertRule, AlertCondition, AlertAction
from dispatch.correlator import Correlator, MatchEvent
from dispatch.incident   import IncidentManager
from dispatch.notifier   import Notifier, NotifierRegistry

__all__ = [
    "RuleBook",
    "AlertRule",
    "AlertCondition",
    "AlertAction",
    "Correlator",
    "MatchEvent",
    "IncidentManager",
    "Notifier",
    "NotifierRegistry",
]