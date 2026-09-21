from __future__ import annotations

from http import HTTPStatus
import json

import pytest

from evolver_server import evolver_controller
from evolver_server.central_store import JsonBootstrapCentralControllerStore, configured_store


@pytest.fixture(autouse=True)
def approved_enrollment_endpoints(monkeypatch):
    monkeypatch.setenv(
        "META_WEBUI_EVOLVER_CONTROLLER_ENDPOINTS",
        '[{"id":"central","label":"Central","url":"https://central","controller_reachable":true,"enabled":true},'
        '{"id":"webui","label":"WebUI","url":"https://webui","controller_reachable":true,"enabled":true},'
        '{"id":"webui-example","label":"WebUI example","url":"https://webui.example","controller_reachable":true,"enabled":true},'
        '{"id":"webui-local","label":"WebUI local","url":"https://webui:18086","controller_reachable":true,"enabled":true}]',
    )


def test_enrollment_token_requires_approved_endpoint_and_supports_endpoint_id(tmp_path):
    rejected, response = evolver_controller.create_enrollment_token(
        server_url="https://attacker.example", state_root=tmp_path,
    )
    assert rejected == HTTPStatus.BAD_REQUEST
    assert response["kind"] == "BadRequest"

    created, token = evolver_controller.create_enrollment_token(
        endpoint_id="webui-example", state_root=tmp_path,
    )
    assert created == HTTPStatus.CREATED
    assert token["endpoint_id"] == "webui-example"
    assert token["server_url"] == "https://webui.example"

    mismatch, _ = evolver_controller.create_enrollment_token(
        endpoint_id="webui-example", server_url="https://central", state_root=tmp_path,
    )
    assert mismatch == HTTPStatus.BAD_REQUEST
    unavailable, _ = evolver_controller.create_enrollment_token(
        endpoint_id="missing", state_root=tmp_path,
    )
    assert unavailable == HTTPStatus.BAD_REQUEST
    invalid_id, _ = evolver_controller.create_enrollment_token(
        endpoint_id="", state_root=tmp_path,
    )
    assert invalid_id == HTTPStatus.BAD_REQUEST

    insecure, _ = evolver_controller.create_enrollment_token(
        server_url="http://webui", state_root=tmp_path,
    )
    assert insecure == HTTPStatus.BAD_REQUEST


def test_enrollment_uses_persisted_server_url_without_revalidating_old_token(tmp_path, monkeypatch):
    created, token = evolver_controller.create_enrollment_token(
        endpoint_id="central", state_root=tmp_path,
    )
    assert created == HTTPStatus.CREATED
    monkeypatch.setenv("META_WEBUI_EVOLVER_CONTROLLER_ENDPOINTS", "[]")
    enrolled, response = evolver_controller.enroll(
        {"controller_id": "edge-old", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path,
    )
    assert enrolled == HTTPStatus.CREATED
    assert response["binding"]["server_url"] == "https://central"


def test_sensitive_http_operations_fail_closed_without_deployment_operator(tmp_path, monkeypatch):
    monkeypatch.setenv(evolver_controller.STATE_ROOT_ENV, str(tmp_path))
    status, response = evolver_controller.dispatch(
        "POST", "/api/evolver/enrollment-tokens", {"server_url": "https://webui.example"},
    )
    assert status == HTTPStatus.UNAUTHORIZED
    assert response["kind"] == "OperatorAuthenticationRequired"


def test_trusted_perimeter_identity_authorizes_only_its_declared_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv(evolver_controller.STATE_ROOT_ENV, str(tmp_path))
    monkeypatch.setenv("META_WEBUI_EVOLVER_TRUSTED_OPERATOR_HEADER", "X-Verified-Operator")
    monkeypatch.setenv("META_WEBUI_EVOLVER_OPERATOR_ROLES", json.dumps({"alice": ["manage_controller", "operate_run"]}))
    operator = evolver_controller.operator_from_headers({"X-Verified-Operator": "alice"})
    assert operator is not None and operator.subject == "alice"
    created, token = evolver_controller.dispatch(
        "POST", "/api/evolver/enrollment-tokens", {"server_url": "https://webui.example"}, operator=operator, state_root=tmp_path,
    )
    assert created == HTTPStatus.CREATED
    enrolled, response = evolver_controller.enroll(
        {"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path,
    )
    assert enrolled == HTTPStatus.CREATED
    synced, _ = evolver_controller.sync(
        {"controller_id": "edge-a", "controller_generation": 1,
         "recovery_summary": {"runs": [{"id": "run-a", "current_revision": 1}]}},
        credential=response["credential"], state_root=tmp_path,
    )
    assert synced == HTTPStatus.OK
    queued, command = evolver_controller.dispatch(
        "POST", "/api/evolver/runs/run-a/commands", {"action": "pause", "expected_revision": 1}, operator=operator, state_root=tmp_path,
    )
    assert queued == HTTPStatus.ACCEPTED
    assert command["command"]["requested_by"] == "alice"
    assert command["command"]["auth_source"] == "trusted_header:X-Verified-Operator"
    denied, denial = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/edge-a/recovery", {}, operator=operator,
    )
    assert denied == HTTPStatus.FORBIDDEN
    assert denial["kind"] == "OperatorPermissionDenied"


def test_request_header_is_not_identity_without_trusted_proxy_proof(monkeypatch):
    monkeypatch.setenv("META_WEBUI_EVOLVER_TRUSTED_OPERATOR_HEADER", "X-Verified-Operator")
    monkeypatch.setenv("META_WEBUI_EVOLVER_OPERATOR_ROLES", json.dumps({"alice": ["manage_controller"]}))
    assert evolver_controller.operator_from_request({"X-Verified-Operator": "alice"}, None) is None


def test_command_wait_is_bounded_generation_fenced_and_safe_stop_prioritized(tmp_path):
    token_status, token = evolver_controller.create_enrollment_token(server_url="https://webui", state_root=tmp_path)
    assert token_status == HTTPStatus.CREATED
    enrolled, result = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    assert enrolled == HTTPStatus.CREATED
    operator = evolver_controller.OperatorIdentity("alice", "test", frozenset({"operate_run"}))
    _, lease = evolver_controller.manual_control_lease("edge-a", {"ttl_seconds": 60}, operator=operator, state_root=tmp_path)
    _, ordinary = evolver_controller.manual_control_command("edge-a", {"operation": "stir_pulse", "duration_ms": 100, "ttl_seconds": 10}, operator=operator, state_root=tmp_path)
    _, stop = evolver_controller.manual_control_command("edge-a", {"operation": "safe_stop", "ttl_seconds": 10, "idempotency_key": "stop-2"}, operator=operator, state_root=tmp_path)
    status, response = evolver_controller.wait_for_command("edge-a", {"controller_generation": 1, "last_cursor": 0, "wait_seconds": 0}, credential=result["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK and response["command"]["command_id"] == stop["command"]["command_id"]
    status, response = evolver_controller.wait_for_command("edge-a", {"controller_generation": 1, "last_cursor": response["cursor"], "wait_seconds": 0}, credential=result["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK and response["command"]["command_id"] == ordinary["command"]["command_id"]


def test_identity_tokens_and_enrollment_survive_central_restart(tmp_path):
    first_status, first = evolver_controller.create_enrollment_token(server_url="https://webui:18086", state_root=tmp_path)
    assert first_status == HTTPStatus.CREATED
    enrolled_status, enrolled = evolver_controller.enroll(
        {"controller_id": "edge-a", "public_key_fingerprint": "edge-public", "enrollment_token": first["enrollment_token"]}, state_root=tmp_path,
    )
    assert enrolled_status == HTTPStatus.CREATED
    assert enrolled["binding"]["controller_generation"] == 1
    assert enrolled["binding"]["webui_controller_id"] == first["webui_controller"]["id"]

    # The secret is single use, while the WebUI identity is durable state.
    rejected_status, _ = evolver_controller.enroll(
        {"controller_id": "edge-b", "enrollment_token": first["enrollment_token"]}, state_root=tmp_path,
    )
    assert rejected_status == HTTPStatus.UNAUTHORIZED
    next_status, next_token = evolver_controller.create_enrollment_token(server_url="https://webui:18086", state_root=tmp_path)
    assert next_status == HTTPStatus.CREATED
    assert next_token["webui_controller"] == first["webui_controller"]


def test_existing_json_install_is_a_one_time_bootstrap_source(tmp_path, monkeypatch):
    """The compatibility file remains readable for migration, never secrets in UI config."""
    path = evolver_controller.state_path(tmp_path)
    legacy = JsonBootstrapCentralControllerStore(path)
    legacy.save({"webui_controller": {"id": "webui-preserved", "public_key_fingerprint": "fingerprint", "created_at": "2025-01-01T00:00:00Z"}, "controllers": {}}, 0)
    assert legacy.load()[0]["webui_controller"]["id"] == "webui-preserved"
    monkeypatch.setenv(evolver_controller.STATE_ROOT_ENV, str(tmp_path))
    # An explicitly supplied root is deliberately the import/test seam; a
    # configured production DB instead selects PostgresCentralControllerStore.
    assert isinstance(configured_store(json_path=path, explicit_state_root=True), JsonBootstrapCentralControllerStore)


def test_unmanaged_compatibility_state_cannot_alias_stale_managed_provenance(tmp_path, monkeypatch):
    root_a = tmp_path / "root-a"
    root_b = tmp_path / "root-b"
    path_a = evolver_controller.state_path(root_a)
    path_b = evolver_controller.state_path(root_b)
    evolver_controller._write(path_a, {"root": "a"})
    evolver_controller._write(path_b, {"root": "b"})

    monkeypatch.setattr(evolver_controller, "id", lambda value: 7, raising=False)
    evolver_controller._state(path_a)
    unmanaged = evolver_controller._read(path_b)
    unmanaged["mutation"] = "belongs-to-b"
    evolver_controller._write(path_b, unmanaged)

    assert evolver_controller._read(path_a) == {"root": "a"}
    assert evolver_controller._read(path_b) == {"root": "b", "mutation": "belongs-to-b"}


def test_authenticated_sync_is_fenced_deduplicated_and_persistent(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui:18086", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    body = {
        "controller_id": "edge-a", "controller_generation": 1,
        "heartbeat": {"state": "running"}, "inventory": [{"id": "instrument-a"}],
        "event_batches": [{"run_id": "run-a", "records": [{"event_id": "event-1", "run_id": "run-a", "sequence": 1}]}],
        "command_acknowledgements": [{"command_id": "command-1", "disposition": "completed"}],
        "telemetry_batches": [{"stream_id": "od", "first_sequence": 1, "last_sequence": 2, "records": [
            {"stream_id": "od", "sequence": 1, "payload": {"od": 0.1}}, {"stream_id": "od", "sequence": 2, "payload": {"od": 0.2}}]}],
        "recovery_summary": {"id": "recovery-1"},
        "history_batches": [{"fact_type": "event", "stream_id": "run-a", "records": [
            {"fact_id": "event-1", "run_id": "run-a", "sequence": 1,
             "occurred_at": "2026-09-01T00:00:00Z", "payload": {"event_type": "started"}}]},
            {"fact_type": "telemetry", "stream_id": "od", "records": [
            {"fact_id": "telemetry:od:1", "stream_id": "od", "sequence": 1,
             "captured_at": "2026-09-01T00:00:01Z", "payload": {"od": 0.1}}]}],
    }
    status, response = evolver_controller.sync(body, credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK
    assert response["accepted_generation"] == 1
    assert response["webui_controller"] == enrolled["webui_controller"]
    # Retry of the same batch is accepted and does not duplicate the event.
    assert evolver_controller.sync(body, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK
    persisted = evolver_controller._read(evolver_controller.state_path(tmp_path))
    controller = persisted["controllers"]["edge-a"]
    assert len(controller["events"]) == 1
    assert controller["event_cursors"] == {"run-a": 1}
    assert controller["telemetry_cursors"] == {"od": 2}
    assert len(controller["history"]) == 2
    assert evolver_controller.sync(body, credential=enrolled["credential"], state_root=tmp_path)[1]["history_projection"] == controller["history"]


def test_history_replay_is_idempotent_and_changed_fact_is_conflict(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    base = {"controller_id": "edge-a", "controller_generation": 1, "history_batches": [{
        "fact_type": "event", "stream_id": "run-a", "records": [{"fact_id": "fact-1", "run_id": "run-a", "sequence": 1, "payload": {"state": "running"}}]}]}
    assert evolver_controller.sync(base, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK
    assert evolver_controller.sync(base, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK
    changed = {**base, "history_batches": [{"fact_type": "event", "stream_id": "run-a", "records": [{"fact_id": "fact-1", "run_id": "run-a", "sequence": 1, "payload": {"state": "stopped"}}]}]}
    status, response = evolver_controller.sync(changed, credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.BAD_REQUEST and response["kind"] == "InvalidSyncBatch"
    state = evolver_controller._read(evolver_controller.state_path(tmp_path))
    assert len(state["controllers"]["edge-a"]["history"]) == 1


def test_cursor_sync_retries_only_unacknowledged_records(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    def body(start: int, end: int):
        return {"controller_id": "edge-a", "controller_generation": 1,
                "event_batches": [{"run_id": "run", "records": [{"run_id": "run", "sequence": sequence, "event_type": "sample"} for sequence in range(start, end + 1)]}],
                "telemetry_batches": [{"stream_id": "run:vial:od", "first_sequence": start, "last_sequence": end,
                                       "records": [{"stream_id": "run:vial:od", "sequence": sequence, "payload": {"value": sequence}} for sequence in range(start, end + 1)]}]}
    status, accepted = evolver_controller.sync(body(1, 75), credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK and accepted["event_cursors"]["run"] == 75
    status, response = evolver_controller.sync(body(76, 100), credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK
    assert response["event_cursors"]["run"] == 100
    assert response["telemetry_cursors"]["run:vial:od"] == 100
    # A response loss causes a retry; central folds the batch by explicit
    # stream/sequence identity and acknowledges its durable high watermark.
    assert evolver_controller.sync(body(76, 100), credential=enrolled["credential"], state_root=tmp_path)[1]["telemetry_cursors"]["run:vial:od"] == 100
    stored = evolver_controller._read(evolver_controller.state_path(tmp_path))["controllers"]["edge-a"]
    assert len(stored["events"]) == len(stored["telemetry"]) == 100

    stale_status, stale = evolver_controller.sync({"controller_id": "edge-a", "controller_generation": 0}, credential=enrolled["credential"], state_root=tmp_path)
    assert stale_status == HTTPStatus.CONFLICT
    assert stale["kind"] == "GenerationConflict"
    assert stale["webui_controller"] == enrolled["webui_controller"]


def test_command_delivery_is_generation_fenced(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    evolver_controller.queue_command("edge-a", {"command_id": "pause-a", "controller_generation": 1, "command_kind": "pause_run"}, state_root=tmp_path)
    status, response = evolver_controller.sync({"controller_id": "edge-a", "controller_generation": 1}, credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK
    assert [command["command_id"] for command in response["commands"]] == ["pause-a"]


def test_sync_persists_and_projects_latest_typed_hardware_observation(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    observation = {
        "source": "physical", "connection_state": "disconnected", "probe_outcome": "timeout",
        "transport": {"kind": "usb_serial", "candidates": ["/dev/ttyACM0"]},
        "transport_evidence": {"event": "probe_failed", "reason": "timeout", "detail": "x" * 1000},
        "observed_at": "2026-08-31T12:00:00+00:00",
    }
    status, _ = evolver_controller.sync({"controller_id": "edge-a", "controller_generation": 1,
                                         "hardware_observation": observation}, credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK
    persisted = evolver_controller._read(evolver_controller.state_path(tmp_path))["controllers"]["edge-a"]["hardware_observation"]
    assert persisted["probe_outcome"] == "timeout"
    assert persisted["diagnostic"] == "timeout"
    assert persisted["recommended_action"] == "retry_probe"
    assert len(persisted["transport_evidence"]["detail"]) == 256

    status, projected = evolver_controller.controllers(controller_id="edge-a", state_root=tmp_path)
    detected = projected["controller"]["detected_hardware"][0]
    assert status == HTTPStatus.OK
    assert projected["controller"]["connection_state"] == "connected"
    assert detected["connection_state"] == "disconnected"
    assert detected["probe_outcome"] == "timeout"
    assert detected["transport"]["candidates"] == ["/dev/ttyACM0"]


@pytest.mark.parametrize(
    ("newer_outcome", "older_outcome"),
    [("open", "timeout"), ("timeout", "open")],
    ids=["newer-success-then-older-timeout", "newer-timeout-then-older-success"],
)
def test_sync_ignores_delayed_hardware_observation(tmp_path, newer_outcome, older_outcome):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll(
        {"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path,
    )
    base = {"controller_id": "edge-a", "controller_generation": 1}
    newer = {**base, "hardware_observation": {"probe_outcome": newer_outcome, "observed_at": "2026-08-31T12:00:02Z"}}
    older = {**base, "hardware_observation": {"probe_outcome": older_outcome, "observed_at": "2026-08-31T12:00:01Z"}}

    assert evolver_controller.sync(newer, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK
    assert evolver_controller.sync(older, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK

    stored = evolver_controller._read(evolver_controller.state_path(tmp_path))["controllers"]["edge-a"]["hardware_observation"]
    assert stored["probe_outcome"] == newer_outcome
    assert stored["observed_at"] == "2026-08-31T12:00:02Z"



def test_legacy_hardware_projection_does_not_replace_typed_observation(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    base = {"controller_id": "edge-a", "controller_generation": 1}
    typed = {**base, "hardware_observation": {"connection_state": "disconnected", "probe_outcome": "timeout",
                                               "transport_evidence": {"reason": "timeout"}}}
    assert evolver_controller.sync(typed, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK
    legacy = {**base, "detected_hardware": [{"connection_state": "connected", "probe_outcome": "open"}]}
    assert evolver_controller.sync(legacy, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK
    stored = evolver_controller._read(evolver_controller.state_path(tmp_path))["controllers"]["edge-a"]["hardware_observation"]
    assert stored["probe_outcome"] == "timeout"


def test_central_queue_rejects_run_target_not_owned_by_controller(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    evolver_controller.sync({"controller_id": "edge-a", "controller_generation": 1,
                             "recovery_summary": {"runs": [{"id": "run-a", "current_revision": 0}]}},
                            credential=enrolled["credential"], state_root=tmp_path)
    with pytest.raises(ValueError, match="does not belong"):
        evolver_controller.queue_command("edge-a", {"command_id": "wrong-run", "controller_generation": 1,
                                                     "command_kind": "pause_run", "run_id": "run-b"}, state_root=tmp_path)


def test_webui_run_mutation_is_queued_and_revision_fenced(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    evolver_controller.sync({"controller_id": "edge-a", "controller_generation": 1,
                             "recovery_summary": {"runs": [{"id": "run-a", "current_revision": 3, "state": "running"}]}}, credential=enrolled["credential"], state_root=tmp_path)
    status, queued = evolver_controller.mutate_run("run-a", {"action": "pause", "expected_revision": 3}, state_root=tmp_path)
    assert status == HTTPStatus.ACCEPTED
    assert queued["command"]["command_kind"] == "pause_run"
    status, stale = evolver_controller.mutate_run("run-a", {"action": "stop", "expected_revision": 2}, state_root=tmp_path)
    assert status == HTTPStatus.CONFLICT and stale["kind"] == "StaleRunRevision"


def test_terminal_command_acknowledgement_retires_delivery_but_keeps_audit_record(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    evolver_controller.queue_command("edge-a", {"command_id": "pause-a", "controller_generation": 1, "command_kind": "pause_run"}, state_root=tmp_path)
    sync_body = {"controller_id": "edge-a", "controller_generation": 1}

    first_status, first = evolver_controller.sync(sync_body, credential=enrolled["credential"], state_root=tmp_path)
    assert first_status == HTTPStatus.OK
    assert [command["command_id"] for command in first["commands"]] == ["pause-a"]

    acknowledgement = {**sync_body, "command_acknowledgements": [{"command_id": "pause-a", "disposition": "completed", "observed_revision": 2}]}
    second_status, second = evolver_controller.sync(acknowledgement, credential=enrolled["credential"], state_root=tmp_path)
    assert second_status == HTTPStatus.OK
    assert second["commands"] == []
    # Retried acknowledgement remains safe and does not resurrect delivery.
    assert evolver_controller.sync(acknowledgement, credential=enrolled["credential"], state_root=tmp_path)[1]["commands"] == []

    persisted = evolver_controller._read(evolver_controller.state_path(tmp_path))
    command = persisted["commands"]["edge-a"][0]
    assert command["disposition"] == "completed"
    assert command["acknowledgement"]["observed_revision"] == 2


def test_expired_manual_command_is_persisted_and_not_returned_by_sync(tmp_path):
    operator = evolver_controller.OperatorIdentity("alice", "test", frozenset({"operate_run"}))
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    status, queued = evolver_controller.manual_control_command(
        "edge-a", {"operation": "safe_stop", "ttl_seconds": 1}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.ACCEPTED
    command_id = queued["command"]["command_id"]
    state = evolver_controller._read(evolver_controller.state_path(tmp_path))
    state["commands"]["edge-a"][0]["expires_at"] = "2000-01-01T00:00:00Z"
    evolver_controller._write(evolver_controller.state_path(tmp_path), state)

    sync_status, response = evolver_controller.sync(
        {"controller_id": "edge-a", "controller_generation": 1}, credential=enrolled["credential"], state_root=tmp_path)
    assert sync_status == HTTPStatus.OK
    assert response["commands"] == []
    projected = next(item for item in response["command_projection"] if item["command_id"] == command_id)
    assert projected["disposition"] == "expired"
    assert projected["delivery_eligible"] is False
    persisted = evolver_controller._read(evolver_controller.state_path(tmp_path))["commands"]["edge-a"][0]
    assert persisted["disposition"] == "expired"
    assert persisted["delivery_eligible"] is False


def test_controller_projection_is_read_only_and_redacts_credentials(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    status, response = evolver_controller.controllers(state_root=tmp_path)
    assert status == HTTPStatus.OK
    assert response["controllers"][0]["id"] == "edge-a"
    assert "credential" not in response["controllers"][0]
    detail_status, detail = evolver_controller.controllers(controller_id="edge-a", state_root=tmp_path)
    assert detail_status == HTTPStatus.OK
    assert detail["controller"]["binding"] == enrolled["binding"]


def test_edge_fact_projections_are_bounded_and_keep_intent_distinct(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://central", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    body = {
        "controller_id": "edge-a", "controller_generation": enrolled["binding"]["controller_generation"],
        "telemetry_batches": [{"stream_id": "run-a:od", "first_sequence": 1, "last_sequence": 1,
                               "records": [{"stream_id": "run-a:od", "sequence": 1, "run_id": "run-a", "od": 0.4}]}],
        "event_batches": [{"run_id": "run-a", "records": [{"run_id": "run-a", "sequence": 1, "event_type": "run_started"}]}],
        "command_acknowledgements": [{"command_id": "command-1", "disposition": "completed"}],
    }
    assert evolver_controller.sync(body, credential=enrolled["credential"], state_root=tmp_path)[0] == HTTPStatus.OK
    status, payload = evolver_controller.edge_facts(controller_id="edge-a", run_id="run-a", limit=1, state_root=tmp_path)
    assert status == HTTPStatus.OK
    assert payload["telemetry"][0]["stream_id"] == "run-a:od"
    assert payload["events"][0]["event_type"] == "run_started"
    assert payload["measurements"] == []  # uncalibrated derived values are not measurements
    assert payload["evidence"][0]["disposition"] == "completed"
    assert "credential_digest" not in repr(payload)
    status, routed = evolver_controller.dispatch("GET", "/api/evolver/controllers/edge-a/telemetry",
                                                  None, query="run_id=run-a&limit=1", state_root=tmp_path)
    assert status == HTTPStatus.OK and len(routed["telemetry"]) == 1


def test_instrument_and_maintenance_projections_are_read_only_and_bounded(tmp_path, monkeypatch):
    monkeypatch.setenv(evolver_controller.STATE_ROOT_ENV, str(tmp_path))
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    status, _ = evolver_controller.sync({
        "controller_id": "edge-a", "controller_generation": 1,
        "heartbeat": {"state": "running", "controller_software_release": "1.2.3", "update_policy": "when_idle", "hardware_service_health": "healthy"},
        "inventory": [{"id": "instrument-a", "source": "physical", "identity_state": "provisioned", "connection_state": "connected",
                       "transport": {"path": "/dev/ttyACM0"}, "vial_positions": [{"id": "vial-a", "position_index": 0}]}],
    }, credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK
    inventory_status, inventory = evolver_controller.dispatch("GET", "/api/evolver/instruments", None, state_root=tmp_path)
    assert inventory_status == HTTPStatus.OK
    assert inventory["instruments"][0]["controller_id"] == "edge-a"
    assert inventory["instruments"][0]["vial_positions"][0]["id"] == "vial-a"
    detail_status, detail = evolver_controller.dispatch("GET", "/api/evolver/instruments/instrument-a", None, state_root=tmp_path)
    assert detail_status == HTTPStatus.OK and detail["instrument"]["source"] == "physical"
    maintenance_status, maintenance = evolver_controller.dispatch("GET", "/api/evolver/maintenance", None, state_root=tmp_path)
    assert maintenance_status == HTTPStatus.OK
    assert maintenance["maintenance"][0]["software_release"] == "1.2.3"
    assert "credential" not in repr(inventory)


def test_explicit_recovery_manifest_is_operationally_separate_and_diffed_by_stable_content_identity(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://webui.example", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    requested_status, requested = evolver_controller.request_recovery_manifest("edge-a", state_root=tmp_path)
    assert requested_status == HTTPStatus.ACCEPTED
    assert requested["command"]["command_kind"] == "request_recovery_manifest"

    manifest = {"id": "manifest-a", "controller_id": "edge-a", "controller_generation": 1,
                "runs": [{"id": "run-live", "current_revision": 4, "state": "running"}],
                "source_metadata": [
                    {"id": "source-identical", "revision": "2", "digest": "same", "content": {"x": 1}},
                    {"id": "source-missing", "revision": "1", "digest": "missing", "content": {"x": 2}},
                    {"id": "source-conflict", "revision": "3", "digest": "edge", "content": {"x": 3}},
                    {"id": "source-persisted-list", "revision": "4", "digest": "list-same", "content": {"x": 4}},
                    {"id": "source-persisted-list-conflict", "revision": "5", "digest": "list-edge", "content": {"x": 5}},
                ]}
    state = evolver_controller._read(evolver_controller.state_path(tmp_path))
    state["content_snapshots"] = {
        "source-identical": {"2": {"id": "source-identical", "revision": "2", "digest": "same", "content": {"x": 1}}},
        "source-conflict": {"3": {"id": "source-conflict", "revision": "3", "digest": "central", "content": {"x": 9}}},
        "source-persisted-list": [{"id": "source-persisted-list", "revision": "4", "digest": "list-same", "content": {"x": 4}}],
        "source-persisted-list-conflict": [{"id": "source-persisted-list-conflict", "revision": "5", "digest": "list-central", "content": {"x": 9}}],
    }
    evolver_controller._write(evolver_controller.state_path(tmp_path), state)
    # The edge replies to the explicit request durably; this is not part of
    # routine summary sync and does not block live run projection.
    status, _ = evolver_controller.sync({"controller_id": "edge-a", "controller_generation": 1,
        "command_acknowledgements": [{"command_id": requested["command"]["command_id"], "disposition": "completed", "recovery_manifest": manifest}],
    }, credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK
    assert evolver_controller.runs(state_root=tmp_path)[1]["runs"][0]["id"] == "run-live"

    diff_status, diff = evolver_controller.recovery_diff("edge-a", state_root=tmp_path)
    assert diff_status == HTTPStatus.OK
    assert {item["object_id"]: item["state"] for item in diff["items"]} == {
        "source-identical": "identical", "source-missing": "missing_central", "source-conflict": "conflict",
        "source-persisted-list": "identical", "source-persisted-list-conflict": "conflict"}
    import_status, imported = evolver_controller.import_recovery_snapshot("edge-a", {"snapshot_id": "source-missing", "action": "import"}, state_root=tmp_path)
    assert import_status == HTTPStatus.OK and imported["outcome"] == "imported"
    conflict_status, _ = evolver_controller.import_recovery_snapshot("edge-a", {"snapshot_id": "source-conflict", "action": "import"}, state_root=tmp_path)
    assert conflict_status == HTTPStatus.CONFLICT
    fork_status, forked = evolver_controller.import_recovery_snapshot("edge-a", {"snapshot_id": "source-conflict", "action": "fork"}, state_root=tmp_path)
    assert fork_status == HTTPStatus.OK and forked["fork_id"].startswith("recovered-source-conflict-")
