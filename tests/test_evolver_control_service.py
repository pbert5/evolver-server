from __future__ import annotations

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
    assert conflict["expected_generation"] == 1

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
