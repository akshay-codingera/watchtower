"""``/api/devices`` — device registry served by ``beacon.*``."""

from __future__ import annotations

import logging
from typing import Any, Final

from flask import Blueprint, request

from beacon import cartographer as _cartographer  # type: ignore[import-not-found]
from beacon import herald as _herald  # type: ignore[import-not-found]
from beacon import sonar as _sonar  # type: ignore[import-not-found]
from beacon import topology as _topology  # type: ignore[import-not-found]

from portal.middleware import login_required, rate_limit, role_required
from portal.responses import fail, ok

_LOG: Final = logging.getLogger(__name__)

bp = Blueprint("api_registry", __name__, url_prefix="/api")


def _device_to_dict(device: Any) -> dict[str, Any]:
    if isinstance(device, dict):
        return device
    if hasattr(device, "to_dict"):
        return dict(device.to_dict())
    return {
        "id": getattr(device, "id", None),
        "ip": getattr(device, "ip", None),
        "hostname": getattr(device, "hostname", None),
        "mac": getattr(device, "mac", None),
        "classification": getattr(device, "classification", None),
        "last_seen": getattr(device, "last_seen", None),
        "status": getattr(device, "status", None),
    }


@bp.get("/devices")
@login_required
def list_devices() -> Any:
    """Return the current device inventory from ``beacon.herald``."""
    devices = _herald.list_devices(
        classification=request.args.get("type") or None,
        status=request.args.get("status") or None,
        search=request.args.get("q") or None,
    )
    return ok({"items": [_device_to_dict(d) for d in devices]})


@bp.get("/devices/<device_id>")
@login_required
def get_device(device_id: str) -> Any:
    device = _herald.get_device(device_id)
    if device is None:
        return fail("not_found", "Device not found", status=404)
    return ok(_device_to_dict(device))


@bp.post("/devices")
@login_required
@role_required("admin", "operator")
@rate_limit(capacity=30, per_seconds=60.0)
def register_device() -> Any:
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return fail("validation_error", "ip is required", status=400)
    hostname = (body.get("hostname") or "").strip() or None
    classification = (body.get("classification") or "").strip() or None
    device = _herald.register_device(ip=ip, hostname=hostname, classification=classification)
    return ok(_device_to_dict(device), status=201)


@bp.delete("/devices/<device_id>")
@login_required
@role_required("admin")
def remove_device(device_id: str) -> Any:
    removed = _herald.remove_device(device_id)
    if not removed:
        return fail("not_found", "Device not found", status=404)
    return ok({"id": device_id, "removed": True})


@bp.get("/devices/<device_id>/status")
@login_required
def device_status(device_id: str) -> Any:
    device = _herald.get_device(device_id)
    if device is None:
        return fail("not_found", "Device not found", status=404)
    ip = getattr(device, "ip", None) if not isinstance(device, dict) else device.get("ip")
    if not ip:
        return fail("validation_error", "Device has no IP", status=400)
    reachable = _sonar.ping_status(ip)
    return ok({"id": device_id, "ip": ip, "reachable": bool(reachable)})


@bp.post("/devices/<device_id>/classify")
@login_required
@role_required("admin", "operator")
def classify(device_id: str) -> Any:
    device = _herald.get_device(device_id)
    if device is None:
        return fail("not_found", "Device not found", status=404)
    classification = _cartographer.classify_device(device)
    return ok({"id": device_id, "classification": classification})


@bp.get("/topology")
@login_required
def topology_graph() -> Any:
    """Return LLDP/CDP-derived nodes and edges for the network map."""
    graph = _topology.get_topology()
    if hasattr(graph, "to_dict"):
        graph = graph.to_dict()
    return ok(graph)


__all__ = ["bp"]
