"""HTTP entrypoint for controller-facing eVOLVER traffic.

The WebUI is the public gateway.  This server is deliberately small and only
hosts the eVOLVER control-plane contract; it does not load frontend assets or
the general application API.
"""
from __future__ import annotations

import hmac
import argparse
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from typing import Any
from urllib.parse import urlparse

from .. import evolver_controller
from . import contract
from .actions import dispatch as dispatch_action


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


def operator_for_action(action_id: str, headers: Any) -> tuple[HTTPStatus, dict[str, Any]] | None:
    operator = proxy_operator(headers)
    permission = contract.required_permission(action_id)
    if permission:
        return evolver_controller._require_operator(operator, permission)
    return None


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
        if method == "GET" and path == "/api/actions":
            denied = evolver_controller._require_operator(proxy_operator(self.headers), "view")
            if denied:
                self._send(*denied)
                return
            try:
                self._send(HTTPStatus.OK, contract.manifest())
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "action contract unavailable", "kind": "ContractUnavailable"})
            return
        if method == "GET" and path == "/api/meta/actions":
            denied = evolver_controller._require_operator(proxy_operator(self.headers), "view")
            if denied:
                self._send(*denied)
                return
            try:
                self._send(HTTPStatus.OK, {
                    "format": "meta-api-catalog/1",
                    "catalogs": [{"id": "evolver", "catalog": contract.catalog_document()}],
                    "unavailable": [],
                })
            except (OSError, ValueError, json.JSONDecodeError):
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "action contract unavailable", "kind": "ContractUnavailable"})
            return
        projected = contract.match(method, path)
        # Catalog routes below apply their precise action permission. Routes
        # that are intentionally not catalog actions still belong to the
        # human gateway and must not be callable on the raw control socket.
        if projected is None and evolver_controller.route_owner(path) == "human":
            denied = evolver_controller._require_operator(proxy_operator(self.headers), "view")
            if denied:
                self._send(*denied)
                return
        if projected is not None:
            try:
                body = self._body() if method != "GET" else None
            except ValueError as exc:
                self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc), "kind": "BadRequest"})
                return
            if isinstance(body, dict) and isinstance(body.get("action"), str):
                projected = contract.match(method, path, body["action"])
                if projected is None:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": "action does not match route", "kind": "BadRequest"})
                    return
            action_id, path_parameters = projected
            parameters = dict(path_parameters)
            if method == "GET":
                # GET action options are query parameters; retain the catalog's
                # typed validation instead of accepting arbitrary query data.
                for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
                    if values:
                        value: Any = values[-1]
                        spec = contract.operator_actions()[action_id].get("parameters", {}).get(name, {})
                        kind = spec.get("type") if isinstance(spec, dict) else None
                        try:
                            if kind == "integer":
                                value = int(value)
                            elif kind == "number":
                                value = float(value)
                            elif kind == "boolean":
                                value = value.lower() in {"1", "true", "yes", "on"}
                            elif kind in {"json", "object", "array"}:
                                value = json.loads(value)
                        except (TypeError, ValueError, json.JSONDecodeError) as exc:
                            self._send(HTTPStatus.BAD_REQUEST, {"error": f"invalid query parameter {name}: {exc}", "kind": "BadRequest"})
                            return
                        parameters[name] = value
            if isinstance(body, dict):
                parameters.update(body)
            invalid = contract.validate_parameters(action_id, parameters)
            if invalid:
                self._send(HTTPStatus.BAD_REQUEST, {"error": invalid, "kind": "BadRequest"})
                return
            denied = operator_for_action(action_id, self.headers)
            if denied:
                self._send(*denied)
                return
            status, payload = dispatch_action(action_id, parameters, operator=proxy_operator(self.headers))
            self._send(status, payload)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evolver-control")
    commands = parser.add_subparsers(dest="command")
    importer = commands.add_parser("import-legacy-state", help="one-way import of a historical JSON state document")
    importer.add_argument("--source", required=True, type=str)
    importer.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "import-legacy-state":
        from evolver_server.persistence.legacy_import import import_legacy_state

        url = os.environ.get("META_WEBUI_INTERFACE_DATABASE_URL") or os.environ.get("DATABASE_URL")
        if not url:
            parser.error("DATABASE_URL is required for legacy import")
        print(json.dumps(import_legacy_state(args.source, url=url, dry_run=args.dry_run), sort_keys=True))
        return 0
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
