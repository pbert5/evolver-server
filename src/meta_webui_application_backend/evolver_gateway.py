"""Narrow WebUI-to-control-plane gateway; never an arbitrary proxy."""
from __future__ import annotations

import json
import os
from http import HTTPStatus
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import evolver_controller
from .evolver_control.service import CONTROL_SHARED_SECRET_ENV, PROXY_OPERATOR_HEADER, PROXY_PERMISSIONS_HEADER, PROXY_SECRET_HEADER

CONTROL_URL_ENV = "META_WEBUI_EVOLVER_CONTROL_URL"


def dispatch(method: str, path: str, body: Any, *, query: str = "", operator: evolver_controller.OperatorIdentity | None = None,
             authorization: str | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Forward only known eVOLVER routes, preserving a single public origin."""
    base = os.environ.get(CONTROL_URL_ENV, "http://127.0.0.1:18087").rstrip("/")
    secret = os.environ.get(CONTROL_SHARED_SECRET_ENV, "")
    headers = {"Accept": "application/json"}
    if authorization:
        headers["Authorization"] = authorization
    if operator is not None:
        if not secret:
            return HTTPStatus.SERVICE_UNAVAILABLE, {"error": "eVOLVER control gateway is not configured", "kind": "ControlPlaneUnavailable"}
        headers.update({PROXY_SECRET_HEADER: secret, PROXY_OPERATOR_HEADER: operator.subject,
                        PROXY_PERMISSIONS_HEADER: ",".join(sorted(operator.permissions))})
    data = json.dumps(body).encode("utf-8") if body is not None else None
    if data is not None:
        headers["Content-Type"] = "application/json"
    url = f"{base}{path}" + (f"?{query}" if query else "")
    try:
        with urlopen(Request(url, data=data, headers=headers, method=method), timeout=10) as response:
            return HTTPStatus(response.status), _json(response.read())
    except HTTPError as exc:
        return HTTPStatus(exc.code), _json(exc.read())
    except (URLError, TimeoutError, ValueError) as exc:
        return HTTPStatus.SERVICE_UNAVAILABLE, {"error": f"eVOLVER control plane is unavailable: {exc}", "kind": "ControlPlaneUnavailable"}


def _json(raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"error": "invalid response from eVOLVER control plane", "kind": "ControlPlaneUnavailable"}
    return payload if isinstance(payload, dict) else {"error": "invalid response from eVOLVER control plane", "kind": "ControlPlaneUnavailable"}
