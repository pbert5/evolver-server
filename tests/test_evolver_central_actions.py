from http import HTTPStatus

from meta_webui_application_backend import evolver_controller
from meta_webui_application_backend.evolver_control.actions import (
    CentralEvolverActionAdapter,
    UnknownAction,
)


def _operator(*permissions: str) -> evolver_controller.OperatorIdentity:
    return evolver_controller.OperatorIdentity("alice", "test", frozenset(permissions))


def _adapter(tmp_path):
    adapter = CentralEvolverActionAdapter(state_root=tmp_path)
    status, token = adapter.dispatch("enrollment_token", {"server_url": "https://central"},
                                     operator=_operator("manage_controller"))
    assert status == HTTPStatus.CREATED
    status, enrolled = adapter.dispatch("enroll", {"controller_id": "edge-a",
                                                     "enrollment_token": token["enrollment_token"]})
    assert status == HTTPStatus.CREATED
    return adapter, enrolled


def test_adapter_covers_projections_enrollment_and_unknown_actions(tmp_path):
    adapter, enrolled = _adapter(tmp_path)
    status, controllers = adapter.dispatch("controllers")
    assert status == HTTPStatus.OK and controllers["controllers"][0]["id"] == "edge-a"
    status, instruments = adapter.dispatch("evolver.instruments")
    assert status == HTTPStatus.OK and instruments["instruments"] == []
    status, runs = adapter.dispatch("evolver.runs")
    assert status == HTTPStatus.OK and runs["runs"] == []
    assert enrolled["binding"]["controller_generation"] == 1
    try:
        adapter.dispatch("not-a-central-action")
    except UnknownAction:
        pass
    else:
        raise AssertionError("unknown actions must not be silently accepted")


def test_adapter_preserves_authorization_and_queued_command_semantics(tmp_path):
    adapter, _ = _adapter(tmp_path)
    denied, _ = adapter.dispatch("refresh", {"controller_id": "edge-a"})
    assert denied == HTTPStatus.UNAUTHORIZED
    operator = _operator("manage_controller")
    status, queued = adapter.dispatch("controller_refresh", {"controller_id": "edge-a"}, operator=operator)
    assert status == HTTPStatus.ACCEPTED
    command = queued["command"]
    assert command["disposition"] == "queued"
    status, projection = adapter.dispatch("command", {"controller_id": "edge-a", "command_id": command["command_id"]})
    assert status == HTTPStatus.OK
    assert projection["command"]["disposition"] == "queued"


def test_adapter_preserves_generation_revision_and_manual_lease_fencing(tmp_path):
    adapter, enrolled = _adapter(tmp_path)
    operator = _operator("operate_run")
    status, lease = adapter.dispatch("manual_control_lease", {"controller_id": "edge-a", "ttl_seconds": 60}, operator=operator)
    assert status == HTTPStatus.CREATED
    status, command = adapter.dispatch("manual_command", {
        "controller_id": "edge-a", "operation": "stir_pulse", "duration_ms": 100,
        "ttl_seconds": 10, "idempotency_key": "pulse-1",
    }, operator=operator)
    assert status == HTTPStatus.ACCEPTED
    assert command["command"]["controller_generation"] == enrolled["binding"]["controller_generation"]
    status, duplicate = adapter.dispatch("manual_command", {
        "controller_id": "edge-a", "operation": "stir_pulse", "duration_ms": 100,
        "ttl_seconds": 10, "idempotency_key": "pulse-1",
    }, operator=operator)
    assert status == HTTPStatus.ACCEPTED
    assert duplicate["command"]["command_id"] == command["command"]["command_id"]
    status, released = adapter.dispatch("manual_control_lease", {
        "controller_id": "edge-a", "lease_action": "revoke",
    }, operator=operator)
    assert status == HTTPStatus.OK and released["lease"]["status"] == "revoked"
    status, projected = adapter.dispatch("commands", {"controller_id": "edge-a"})
    assert status == HTTPStatus.OK
    assert any(item["command_id"] == command["command"]["command_id"] and item["disposition"] == "rejected_lease"
               for item in projected["commands"])


def test_adapter_exposes_bounded_simulator_safe_stir(tmp_path):
    adapter, _ = _adapter(tmp_path)
    operator = _operator("operate_run")
    status, _ = adapter.dispatch("evolver.controllers.manual.lease",
                                 {"controller_id": "edge-a", "ttl_seconds": 60}, operator=operator)
    assert status == HTTPStatus.CREATED
    status, queued = adapter.dispatch("evolver.controllers.manual.stir", {
        "controller_id": "edge-a", "duration_ms": 100, "channel": 1, "level": 25,
        "ttl_seconds": 10, "idempotency_key": "safe-stir-1",
    }, operator=operator)
    assert status == HTTPStatus.ACCEPTED
    assert queued["command"]["operation"] == "stir_pulse"
    assert queued["command"]["parameters"] == {"channel": 1, "duration_ms": 100, "level": 25}
    status, _ = adapter.dispatch("evolver.controllers.manual.stir", {
        "controller_id": "edge-a", "duration_ms": 1001, "channel": 1, "level": 25,
    }, operator=operator)
    assert status == HTTPStatus.BAD_REQUEST


def test_adapter_routes_recovery_and_resources_through_controller(tmp_path):
    adapter, _ = _adapter(tmp_path)
    operator = _operator("recover_controller", "operate_run")
    status, requested = adapter.dispatch("recovery", {"controller_id": "edge-a", "request": True}, operator=operator)
    assert status == HTTPStatus.ACCEPTED
    assert requested["command"]["command_kind"] == "request_recovery_manifest"
    status, missing = adapter.dispatch("run_resources", {"run_id": "missing"})
    assert status == HTTPStatus.NOT_FOUND
    denied, _ = adapter.dispatch("recovery_import", {"controller_id": "edge-a", "snapshot_id": "x", "action": "ignore"})
    assert denied == HTTPStatus.UNAUTHORIZED
