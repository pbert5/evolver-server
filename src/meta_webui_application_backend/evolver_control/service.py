"""HTTP entrypoint for controller-facing eVOLVER traffic.

The WebUI is the public gateway.  This server is deliberately small and only
hosts the eVOLVER control-plane contract; it does not load frontend assets or
the general application API.
"""
from __future__ import annotations

import hmac
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from typing import Any
from urllib.parse import urlparse

from .. import evolver_controller


CONTROL_SHARED_SECRET_ENV = "META_WEBUI_EVOLVER_CONTROL_SHARED_SECRET"
PROXY_SECRET_HEADER = "X-Meta-Webui-Evolver-Control-Secret"
PROXY_OPERATOR_HEADER = "X-Meta-Webui-Evolver-Operator"
PROXY_PERMISSIONS_HEADER = "X-Meta-Webui-Evolver-Permissions"


def proxy_operator(headers: Any) -> evolver_controller.OperatorIdentity | None:
    """Accept operator context only from the authenticated WebUI gateway."""
    expected = os.environ.get(CONTROL_SHARED_SECRET_ENV, "")
    supplied = headers.get(PROXY_SECRET_HEADER, "")
    if not expected or not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        return None
    subject = headers.get(PROXY_OPERATOR_HEADER)
    permissions = headers.get(PROXY_PERMISSIONS_HEADER, "")
    if not isinstance(subject, str) or not subject.strip():
        return None
    selected = frozenset(item for item in permissions.split(",") if item)
    allowed = selected & evolver_controller._OPERATOR_PERMISSIONS
    return evolver_controller.OperatorIdentity(subject=subject.strip(), source="webui_gateway", permissions=allowed)


class EvolverControlHandler(BaseHTTPRequestHandler):
    server_version = "MetaWebUIEvolverControl/1"

    def do_GET(self) -> None: self._handle("GET")
    def do_POST(self) -> None: self._handle("POST")
    def do_PATCH(self) -> None: self._handle("PATCH")
    def do_DELETE(self) -> None: self._handle("DELETE")

    def _body(self) -> Any:
        length = self.headers.get("Content-Length")
        if not length:
            return None
        try:
            payload = self.rfile.read(int(length))
            return json.loads(payload.decode("utf-8")) if payload else None
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"body is not valid JSON: {exc}") from exc

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if method == "GET" and path == "/health":
            try:
                status, payload = evolver_controller.controllers()
                if status is not HTTPStatus.OK:
                    raise RuntimeError(payload.get("error", "control repository unavailable"))
                self._send(HTTPStatus.OK, {"status": "ok", "repository": "postgres", "webui_controller": payload["webui_controller"]})
            except Exception as exc:  # Health must describe, not hide, DB failure.
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"status": "unavailable", "error": str(exc)})
            return
        if not evolver_controller.handles(path):
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found", "kind": "NotFound"})
            return
        try:
            body = self._body() if method != "GET" else None
        except ValueError as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc), "kind": "BadRequest"})
            return
        status, payload = evolver_controller.dispatch(
            method, path, body, query=parsed.query, authorization=self.headers.get("Authorization"), operator=proxy_operator(self.headers)
        )
        self._send(status, payload)

    def _send(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        print("[evolver-control] " + format % args)


def main() -> None:
    host = os.environ.get("META_WEBUI_EVOLVER_CONTROL_HOST", "127.0.0.1")
    port = int(os.environ.get("META_WEBUI_EVOLVER_CONTROL_PORT", "18087"))
    server = ThreadingHTTPServer((host, port), EvolverControlHandler)
    server.daemon_threads = True
    print(f"eVOLVER Control Plane: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping eVOLVER Control Plane.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
