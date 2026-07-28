"""OpenAPI 3.1 specification served at ``/api/openapi.json`` and ``/api/docs``."""

from __future__ import annotations

from typing import Any, Final

from flask import Blueprint, Response, jsonify, render_template

bp = Blueprint("api_swagger", __name__, url_prefix="/api")

_SPEC: Final[dict[str, Any]] = {
    "openapi": "3.1.0",
    "info": {
        "title": "Watchtower Portal API",
        "version": "1.0.0",
        "description": "HTTP surface of the Watchtower SIEM portal.",
    },
    "servers": [{"url": "/", "description": "Current deployment"}],
    "components": {
        "securitySchemes": {
            "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            "SessionAuth": {"type": "apiKey", "in": "cookie", "name": "watchtower_session"},
        },
        "schemas": {
            "Envelope": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "data": {"type": "object"},
                    "error": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string"},
                            "message": {"type": "string"},
                        },
                    },
                },
            }
        },
    },
    "paths": {
        "/health": {"get": {"summary": "Liveness probe", "responses": {"200": {"description": "OK"}}}},
        "/api/logs": {
            "get": {
                "summary": "List log records",
                "security": [{"SessionAuth": []}],
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}},
                    {"name": "severity", "in": "query", "schema": {"type": "string"}},
                    {"name": "source_ip", "in": "query", "schema": {"type": "string"}},
                    {"name": "since", "in": "query", "schema": {"type": "string", "format": "date-time"}},
                    {"name": "until", "in": "query", "schema": {"type": "string", "format": "date-time"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 500}},
                    {"name": "offset", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {"200": {"description": "Log page"}},
            }
        },
        "/api/logs/{id}": {
            "get": {
                "summary": "Fetch log by id",
                "security": [{"SessionAuth": []}],
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Log record"}, "404": {"description": "Not found"}},
            }
        },
        "/api/logs/export": {"get": {"summary": "Export logs", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Export handle"}}}},
        "/api/stats": {"get": {"summary": "Live counters and aggregates", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Stats"}}}},
        "/api/devices": {
            "get": {"summary": "List devices", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Devices"}}},
            "post": {"summary": "Register device", "security": [{"SessionAuth": []}], "responses": {"201": {"description": "Created"}}},
        },
        "/api/devices/{id}": {
            "get": {"summary": "Get device", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Device"}}},
            "delete": {"summary": "Remove device", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Removed"}}},
        },
        "/api/devices/{id}/status": {"get": {"summary": "Ping device", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Status"}}}},
        "/api/topology": {"get": {"summary": "Network topology graph", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Graph"}}}},
        "/api/incidents": {"get": {"summary": "List incidents", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Incidents"}}}},
        "/api/incidents/{id}": {"get": {"summary": "Get incident", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Incident"}}}},
        "/api/incidents/{id}/ack": {"post": {"summary": "Acknowledge incident", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Acknowledged"}}}},
        "/api/incidents/{id}/resolve": {"post": {"summary": "Resolve incident", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Resolved"}}}},
        "/api/rules": {"get": {"summary": "List alert rules", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Rules"}}}},
        "/api/rules/{id}": {
            "get": {"summary": "Get rule", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Rule"}}},
            "put": {"summary": "Save rule", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Saved"}}},
            "delete": {"summary": "Delete rule", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Removed"}}},
        },
        "/api/webhooks": {
            "get": {"summary": "List webhooks", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Webhooks"}}},
            "post": {"summary": "Create webhook", "security": [{"SessionAuth": []}], "responses": {"201": {"description": "Created"}}},
        },
        "/api/webhooks/{id}": {
            "get": {"summary": "Get webhook", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Webhook"}}},
            "put": {"summary": "Update webhook", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Updated"}}},
            "delete": {"summary": "Delete webhook", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Removed"}}},
        },
        "/api/ingest": {
            "post": {
                "summary": "HTTP ingest endpoint",
                "security": [{"ApiKeyAuth": []}],
                "responses": {"202": {"description": "Accepted"}, "401": {"description": "Unauthorized"}},
            }
        },
        "/api/settings": {"get": {"summary": "Runtime settings", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "Settings"}}}},
        "/stream": {"get": {"summary": "Server-Sent Events", "security": [{"SessionAuth": []}], "responses": {"200": {"description": "SSE stream"}}}},
    },
}


@bp.get("/openapi.json")
def openapi_spec() -> Response:
    return jsonify(_SPEC)


@bp.get("/docs")
def docs() -> str:
    return render_template("codex.html", page_id="codex", spec=_SPEC)


__all__ = ["bp"]
