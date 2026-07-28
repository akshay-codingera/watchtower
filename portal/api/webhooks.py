"""CRUD endpoints for outbound webhook targets.

Persistence and dispatch are owned by ``dispatch.notifier.webhook``.
This module only exposes the HTTP surface.
"""

from __future__ import annotations

import logging
from typing import Any, Final

from flask import Blueprint, request

from dispatch.notifier import webhook as _webhook  # type: ignore[import-not-found]

from portal.middleware import login_required, role_required
from portal.responses import fail, ok

_LOG: Final = logging.getLogger(__name__)

bp = Blueprint("api_webhooks", __name__, url_prefix="/api")


def _to_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    if hasattr(item, "to_dict"):
        return dict(item.to_dict())
    return dict(vars(item))


def _validate(body: dict[str, Any]) -> str | None:
    url = (body.get("url") or "").strip()
    if not url or not (url.startswith("http://") or url.startswith("https://")):
        return "url must be an http(s) URL"
    events = body.get("events") or []
    if not isinstance(events, list) or not events:
        return "events must be a non-empty list"
    for event in events:
        if not isinstance(event, str) or not event:
            return "events must contain non-empty strings"
    return None


@bp.get("/webhooks")
@login_required
def list_webhooks() -> Any:
    items = _webhook.list_webhooks()
    return ok({"items": [_to_dict(w) for w in items]})


@bp.get("/webhooks/<webhook_id>")
@login_required
def get_webhook(webhook_id: str) -> Any:
    item = _webhook.get_webhook(webhook_id)
    if item is None:
        return fail("not_found", "Webhook not found", status=404)
    return ok(_to_dict(item))


@bp.post("/webhooks")
@login_required
@role_required("admin")
def create_webhook() -> Any:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return fail("validation_error", "JSON body required", status=400)
    error = _validate(body)
    if error:
        return fail("validation_error", error, status=400)
    created = _webhook.save_webhook(webhook_id=None, definition=body)
    return ok(_to_dict(created), status=201)


@bp.put("/webhooks/<webhook_id>")
@login_required
@role_required("admin")
def update_webhook(webhook_id: str) -> Any:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return fail("validation_error", "JSON body required", status=400)
    error = _validate(body)
    if error:
        return fail("validation_error", error, status=400)
    updated = _webhook.save_webhook(webhook_id=webhook_id, definition=body)
    if updated is None:
        return fail("not_found", "Webhook not found", status=404)
    return ok(_to_dict(updated))


@bp.delete("/webhooks/<webhook_id>")
@login_required
@role_required("admin")
def delete_webhook(webhook_id: str) -> Any:
    removed = _webhook.delete_webhook(webhook_id)
    if not removed:
        return fail("not_found", "Webhook not found", status=404)
    return ok({"id": webhook_id, "removed": True})


__all__ = ["bp"]
