from __future__ import annotations

from http import HTTPStatus

import pytest

from meta_webui_application_backend import evolver_controller
from meta_webui_application_backend.evolver_control.actions import ACTION_ADAPTERS, UnknownAction, dispatch


APPROVED_CALIBRATION_ACTIONS = {
    "evolver.calibrations.list",
    "evolver.calibrations.show",
    "evolver.calibrations.sessions.create",
    "evolver.calibrations.sessions.observation",
    "evolver.calibrations.sessions.capture",
    "evolver.calibrations.sessions.fit",
    "evolver.calibrations.sessions.accept",
    "evolver.calibrations.sessions.cancel",
    "evolver.calibrations.artifacts.deliver",
    "evolver.calibrations.artifacts.supersede",
    "evolver.calibrations.artifacts.invalidate",
}


def test_approved_calibration_catalog_has_exact_trusted_adapter_coverage() -> None:
    assert {action for action in ACTION_ADAPTERS if action.startswith("evolver.calibrations.")} == (
        APPROVED_CALIBRATION_ACTIONS
    )


@pytest.mark.parametrize(("catalog_id", "expected"), [
    ("evolver.calibrations.list", "list"),
    ("evolver.calibrations.sessions.create", "create"),
    ("evolver.calibrations.sessions.observation", "observation"),
    ("evolver.calibrations.sessions.fit", "fit"),
    ("evolver.calibrations.sessions.accept", "accept"),
    ("evolver.calibrations.sessions.cancel", "cancel"),
    ("evolver.calibrations.sessions.capture", "capture"),
    ("evolver.calibrations.artifacts.deliver", "deliver"),
    ("evolver.calibrations.artifacts.supersede", "supersede"),
    ("evolver.calibrations.artifacts.invalidate", "invalidate"),
])
def test_approved_calibration_actions_delegate_to_authoritative_controller(monkeypatch, catalog_id, expected) -> None:
    calls = []

    def fake(name):
        def invoke(*args, **kwargs):
            calls.append(name)
            return HTTPStatus.OK, {"mapped": name}
        return invoke

    def fake_session(*args, **kwargs):
        calls.append(args[1])
        return HTTPStatus.OK, {"mapped": args[1]}

    monkeypatch.setattr(evolver_controller, "calibrations", fake("list"))
    monkeypatch.setattr(evolver_controller, "create_calibration_session", fake("create"))
    monkeypatch.setattr(evolver_controller, "calibration_session_mutation", fake_session)
    monkeypatch.setattr(evolver_controller, "capture_latest_observation", fake("capture"))
    monkeypatch.setattr(evolver_controller, "deliver_calibration_artifact", fake("deliver"))
    monkeypatch.setattr(evolver_controller, "supersede_calibration_artifact", fake("supersede"))
    monkeypatch.setattr(evolver_controller, "invalidate_calibration_artifact", fake("invalidate"))
    operator = evolver_controller.OperatorIdentity("alice", "test", frozenset({"manage_calibration"}))

    status, result = dispatch(catalog_id, {
        "session_id": "session-1", "artifact_id": "artifact-1",
        "superseding_artifact_id": "artifact-2", "reason": "expired",
        "raw_value": 100, "reference_value": 20,
    }, operator=operator)

    assert status is HTTPStatus.OK
    assert result == {"mapped": expected}
    assert calls == [expected]


def test_calibration_show_delegates_as_a_read_only_detail_projection(monkeypatch) -> None:
    expected = {"calibration": {"id": "calibration-1"}}
    calls = []

    def show(*, calibration_id, state_root):
        calls.append((calibration_id, state_root))
        return HTTPStatus.OK, expected

    monkeypatch.setattr(evolver_controller, "calibrations", show)
    assert dispatch("evolver.calibrations.show", {"calibration_id": "calibration-1"}) == (HTTPStatus.OK, expected)
    assert calls == [("calibration-1", None)]


def test_calibration_adapter_preserves_authorization_and_rejects_retired_od_action() -> None:
    operator = evolver_controller.OperatorIdentity("alice", "test", frozenset())
    status, result = dispatch("evolver.calibrations.sessions.create", {
        "calibration_type": "temperature", "instrument_id": "instrument-1",
    }, operator=operator)
    assert status is HTTPStatus.FORBIDDEN
    assert result["kind"] == "OperatorPermissionDenied"

    with pytest.raises(UnknownAction, match="unknown central eVOLVER action"):
        dispatch("evolver.calibrations.sessions.od_fit", {}, operator=operator)


def test_calibration_adapter_preserves_authoritative_missing_and_invalid_parameter_rejections(tmp_path) -> None:
    operator = evolver_controller.OperatorIdentity("alice", "test", frozenset({"manage_calibration"}))

    missing_status, missing = dispatch(
        "evolver.calibrations.sessions.create", {"calibration_type": "temperature"},
        operator=operator, state_root=tmp_path,
    )
    assert missing_status is HTTPStatus.BAD_REQUEST
    assert missing["kind"] == "BadRequest"

    invalid_status, invalid = dispatch(
        "evolver.calibrations.sessions.create", {
            "calibration_type": "od", "instrument_id": "instrument-1",
        }, operator=operator, state_root=tmp_path,
    )
    assert invalid_status is HTTPStatus.BAD_REQUEST
    assert invalid["kind"] == "BadRequest"
