from http import HTTPStatus

from meta_webui_application_backend import evolver_controller


def test_calibration_event_contract_covers_accept_deliver_and_invalidate(tmp_path):
    operator = evolver_controller.OperatorIdentity(
        subject="operator-a", source="test", permissions=frozenset({"manage_calibration"})
    )
    _, token = evolver_controller.create_enrollment_token(
        server_url="https://webui.example", state_root=tmp_path
    )
    _, enrolled = evolver_controller.enroll(
        {"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]},
        state_root=tmp_path,
    )
    assert evolver_controller.sync(
        {
            "controller_id": "edge-a",
            "controller_generation": 1,
            "inventory": [{"id": "instrument-a", "vial_positions": [{"id": "vial-a"}]}],
        },
        credential=enrolled["credential"],
        state_root=tmp_path,
    )[0] == HTTPStatus.OK

    status, created = evolver_controller.create_calibration_session(
        {"calibration_type": "temperature", "instrument_id": "instrument-a"},
        operator=operator,
        state_root=tmp_path,
    )
    assert status == HTTPStatus.CREATED
    session_id = created["session"]["id"]
    for raw_value, reference_value in ((100, 20), (200, 30)):
        assert evolver_controller.calibration_session_mutation(
            session_id,
            "observation",
            {"raw_value": raw_value, "reference_value": reference_value},
            operator=operator,
            state_root=tmp_path,
        )[0] == HTTPStatus.OK
    assert evolver_controller.calibration_session_mutation(
        session_id, "fit", {}, operator=operator, state_root=tmp_path
    )[0] == HTTPStatus.OK
    status, accepted = evolver_controller.calibration_session_mutation(
        session_id, "accept", {}, operator=operator, state_root=tmp_path
    )
    assert status == HTTPStatus.CREATED
    artifact_id = accepted["artifact"]["id"]

    status, delivered = evolver_controller.deliver_calibration_artifact(
        artifact_id, operator=operator, state_root=tmp_path
    )
    assert status == HTTPStatus.ACCEPTED
    command = delivered["command"]
    stored_ack = {
        "controller_id": "edge-a",
        "controller_generation": 1,
        "command_acknowledgements": [{
            "command_id": command["command_id"],
            "disposition": "stored",
            "artifact_id": artifact_id,
            "artifact_digest": command["artifact_digest"],
        }],
    }
    assert evolver_controller.sync(
        stored_ack, credential=enrolled["credential"], state_root=tmp_path
    )[0] == HTTPStatus.OK
    assert evolver_controller.sync(
        stored_ack, credential=enrolled["credential"], state_root=tmp_path
    )[0] == HTTPStatus.OK
    assert evolver_controller.invalidate_calibration_artifact(
        artifact_id, reason="bad reference", operator=operator, state_root=tmp_path
    )[0] == HTTPStatus.OK

    events = evolver_controller._read(evolver_controller.state_path(tmp_path))["calibration_events"]
    assert [event["event_type"] for event in events] == ["accepted", "distribution_requested", "distribution_stored", "invalidated"]
    for event in events:
        assert {"id", "event_type", "artifact_id", "occurred_at"} <= event.keys()
        assert event["type"] == event["event_type"]
        assert event["at"] == event["occurred_at"]
        assert event["details"]["value"]
    assert events[0]["actor"] == events[0]["by"] == "operator-a"
    assert events[-1]["reason"] == "bad reference"


def test_calibration_workspace_is_a_bounded_read_only_aggregate(tmp_path):
    status, payload = evolver_controller.dispatch(
        "GET", "/api/evolver/calibration-workspace", None, state_root=tmp_path
    )
    assert status is HTTPStatus.OK
    assert set(payload) >= {"calibrations", "instruments", "firmware_supported_procedures"}
    assert evolver_controller.route_owner("/api/evolver/calibration-workspace") == "human"


def test_temperature_derivation_requires_exact_active_target_and_preserves_provenance():
    raw = {
        "controller_id": "controller-a",
        "instrument_id": "instrument-a",
        "vial_position_id": "vial-a",
        "component_id": "component-a",
        "metric": "thermistor_raw",
        "value": 100,
        "stream_id": "instrument-a:temperature",
        "sequence": 7,
    }
    artifact = {
        "id": "artifact-a",
        "calibration_type": "temperature",
        "instrument_id": "instrument-a",
        "vial_position_id": "vial-a",
        "component_id": "component-a",
        "created_at": "2026-08-26T10:00:00Z",
        "coefficients": {"slope": 0.5, "intercept": 10},
        "assessment": {"status": "valid"},
        "artifact_digest": "sha256:artifact-a",
        "distribution": {
            "controller-a": {
                "state": "stored",
                "controller_generation": 3,
            }
        },
    }
    state = {
        "calibration_artifacts": {"artifact-a": artifact},
        "controllers": {"controller-a": {"binding": {"controller_generation": 3}}},
    }
    rows = evolver_controller._calibrated_telemetry(state, [raw])
    assert rows[0] == raw
    assert rows[1]["value"] == 60
    assert rows[1]["calibration_artifact_id"] == "artifact-a"
    assert rows[1]["source_stream_id"] == raw["stream_id"]
    assert rows[1]["source_sequence"] == raw["sequence"]
    assert evolver_controller._active_temperature_artifact(
        state, {**raw, "component_id": "wrong-component"}
    ) is None
    assert evolver_controller._active_temperature_artifact(
        state, {**raw, "vial_position_id": "wrong-vial"}
    ) is None
