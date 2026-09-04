"""Application-owned eVOLVER server endpoint allow-list."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_CONFIG = Path(__file__).resolve().parents[3] / "config" / "server.yaml"


def controller_endpoints() -> list[dict[str, Any]]:
    raw = os.environ.get("META_WEBUI_EVOLVER_CONTROLLER_ENDPOINTS")
    if raw:
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("META_WEBUI_EVOLVER_CONTROLLER_ENDPOINTS is not valid JSON") from exc
    else:
        try:
            import yaml
            loaded = yaml.safe_load(_CONFIG.read_text(encoding="utf-8")) if _CONFIG.is_file() else {}
        except (OSError, ImportError, ValueError) as exc:
            raise ValueError(f"unable to load eVOLVER server endpoint configuration: {exc}") from exc
    records = loaded.get("controller_endpoints", loaded) if isinstance(loaded, dict) else loaded
    if not isinstance(records, list):
        raise ValueError("controller_endpoints must be a list")
    result: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        endpoint = {"id": item.get("id"), "label": item.get("label"), "url": str(item.get("url", "")).rstrip("/"),
                    "controller_reachable": item.get("controller_reachable") is True, "enabled": item.get("enabled") is True,
                    "description": item.get("description"), "priority": item.get("priority", 100)}
        if not isinstance(endpoint["id"], str) or not endpoint["id"] or not isinstance(endpoint["label"], str) or not endpoint["label"]:
            raise ValueError("each controller endpoint requires a stable id and label")
        parsed = urlparse(endpoint["url"])
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError(f"controller endpoint {endpoint['id']} has an invalid URL")
        if endpoint["controller_reachable"] and endpoint["enabled"]:
            result.append(endpoint)
    return sorted(result, key=lambda value: (int(value["priority"]), str(value["id"])))


def select_controller_endpoint(endpoint_id: str | None = None) -> dict[str, Any]:
    endpoints = controller_endpoints()
    if not endpoints:
        raise ValueError("no enabled controller-reachable eVOLVER server endpoint is configured")
    if endpoint_id:
        selected = next((item for item in endpoints if item["id"] == endpoint_id), None)
        if selected is None:
            raise ValueError("selected eVOLVER server endpoint is unavailable")
        return selected
    return endpoints[0]
