from __future__ import annotations

import io
from http import HTTPStatus

from meta_webui_application_backend import evolver_controller
from meta_webui_application_backend.evolver_control import service


def test_control_service_proxy_operator_requires_shared_secret_and_filters_permissions(monkeypatch):
    monkeypatch.setenv(service.CONTROL_SHARED_SECRET_ENV, "gateway-secret")
    headers = {
        service.PROXY_SECRET_HEADER: "gateway-secret",
        service.PROXY_OPERATOR_HEADER: "alice",
        service.PROXY_PERMISSIONS_HEADER: "manage_controller,not-a-permission,operate_run",
    }
    operator = service.proxy_operator(headers)
    assert operator is not None
    assert operator.subject == "alice"
    assert operator.source == "webui_gateway"
    assert operator.permissions == frozenset({"manage_controller", "operate_run"})

    headers[service.PROXY_SECRET_HEADER] = "wrong-secret"
    assert service.proxy_operator(headers) is None
    headers[service.PROXY_SECRET_HEADER] = "gateway-secret"
    headers[service.PROXY_OPERATOR_HEADER] = "   "
    assert service.proxy_operator(headers) is None


def test_machine_sync_requires_credential_and_current_controller_generation(tmp_path):
    token_status, token = evolver_controller.create_enrollment_token(
        server_url="https://central", state_root=tmp_path
    )
    assert token_status == HTTPStatus.CREATED
    enroll_status, enrolled = evolver_controller.enroll(
        {"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]},
        state_root=tmp_path,
    )
    assert enroll_status == HTTPStatus.CREATED

    body = {"controller_id": "edge-a", "controller_generation": 1}
    status, _ = evolver_controller.sync(body, credential="wrong", state_root=tmp_path)
    assert status == HTTPStatus.UNAUTHORIZED

    status, conflict = evolver_controller.sync(
        {**body, "controller_generation": 0},
        credential=enrolled["credential"],
        state_root=tmp_path,
    )
    assert status == HTTPStatus.CONFLICT
    assert conflict["kind"] == "GenerationConflict"

    status, accepted = evolver_controller.sync(
        body, credential=enrolled["credential"], state_root=tmp_path
    )
    assert status == HTTPStatus.OK
    assert accepted["accepted_generation"] == 1

    status, conflict = evolver_controller.wait_for_command(
        "edge-a", {"controller_generation": 2, "last_cursor": 0, "wait_seconds": 0},
        credential=enrolled["credential"], state_root=tmp_path,
    )
    assert status == HTTPStatus.CONFLICT
    assert conflict["kind"] == "GenerationConflict"


def test_catalog_read_actions_require_view_permission(monkeypatch):
    denied = service.operator_for_action("evolver.controllers.list", {})
    assert denied is not None
    denied_status, payload = denied
    assert denied_status == HTTPStatus.UNAUTHORIZED
    assert payload["kind"] == "OperatorAuthenticationRequired"

    operator = evolver_controller.OperatorIdentity("alice", "webui_gateway", frozenset({"operate_run"}))
    monkeypatch.setenv(service.CONTROL_SHARED_SECRET_ENV, "gateway-secret")
    headers = {service.PROXY_SECRET_HEADER: "gateway-secret", service.PROXY_OPERATOR_HEADER: operator.subject,
               service.PROXY_PERMISSIONS_HEADER: ",".join(operator.permissions)}
    denied = service.operator_for_action("evolver.controllers.list", headers)
    assert denied is not None
    denied_status, payload = denied
    assert denied_status == HTTPStatus.FORBIDDEN
    assert payload["kind"] == "OperatorPermissionDenied"


def test_gateway_does_not_forward_human_bearer_to_raw_operator_routes(monkeypatch):
    captured = {}

    class Response:
        status = 200

        def read(self):
            return b'{}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout):
        captured.update(request.headers)
        return Response()

    monkeypatch.setattr("meta_webui_application_backend.evolver_gateway.urlopen", fake_urlopen)
    service_module = __import__("meta_webui_application_backend.evolver_gateway", fromlist=["dispatch"])
    service_module.dispatch("POST", "/api/evolver/runs/run-a/commands", {},
                            authorization="Bearer human-token",
                            operator=evolver_controller.OperatorIdentity("alice", "webui_gateway", frozenset({"operate_run"})))
    assert "Authorization" not in captured


def test_uncatalogued_human_routes_require_gateway_operator_context(monkeypatch):
    handler = service.EvolverControlHandler.__new__(service.EvolverControlHandler)
    handler.path = "/api/evolver/dashboard"
    handler.headers = {}
    handler.rfile = io.BytesIO()
    sent = {}
    monkeypatch.setattr(handler, "_send", lambda status, payload: sent.update(status=status, payload=payload))

    handler._handle("GET")

    assert sent["status"] == HTTPStatus.UNAUTHORIZED
    assert sent["payload"]["kind"] == "OperatorAuthenticationRequired"
