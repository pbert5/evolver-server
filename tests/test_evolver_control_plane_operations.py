from __future__ import annotations

from datetime import timedelta
from http import HTTPStatus
import json

from evolver_server import evolver_controller


def _operator(*permissions: str) -> evolver_controller.OperatorIdentity:
    return evolver_controller.OperatorIdentity("alice", "test", frozenset(permissions))


def _enrolled(tmp_path):
    _, token = evolver_controller.create_enrollment_token(server_url="https://central", state_root=tmp_path)
    _, enrolled = evolver_controller.enroll({"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path)
    return enrolled


def test_freshness_is_distinct_from_connection_and_refresh_is_not_rescan(tmp_path):
    enrolled = _enrolled(tmp_path)
    old = (evolver_controller._now() - timedelta(days=2)).isoformat().replace("+00:00", "Z")
    state = evolver_controller._read(evolver_controller.state_path(tmp_path))
    state["controllers"]["edge-a"].update({"connection_state": "connected", "last_sync_at": old})
    evolver_controller._write(evolver_controller.state_path(tmp_path), state)
    status, projection = evolver_controller.dispatch("GET", "/api/evolver/controllers/edge-a/sync-freshness", None, state_root=tmp_path)
    assert status == HTTPStatus.OK and projection["sync_freshness"]["stale"] is True
    status, refresh = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/refresh", {}, operator=_operator("manage_controller"), state_root=tmp_path)
    assert status == HTTPStatus.ACCEPTED and refresh["command"]["command_kind"] == "central_refresh"
    status, rescan = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/hardware-rescan", {}, operator=_operator("manage_controller"), state_root=tmp_path)
    assert status == HTTPStatus.ACCEPTED and rescan["command"]["command_kind"] == "hardware_rescan"
    assert refresh["command"]["controller_generation"] == rescan["command"]["controller_generation"] == enrolled["binding"]["controller_generation"]


def test_manual_lease_expiry_revocation_and_emergency_release_are_audited(tmp_path):
    _enrolled(tmp_path)
    operator = _operator("operate_run")
    status, acquired = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/manual-control-lease", {"ttl_seconds": 60}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.CREATED
    status, conflict = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/manual-control-lease", {}, operator=_operator("operate_run"), state_root=tmp_path)
    assert status == HTTPStatus.OK  # same holder is idempotently renewable
    status, released = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/manual-control-lease/emergency-release", {}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.OK and released["lease"]["status"] == "emergency_released"
    assert released["safe_stop_intent"]["command_kind"] == "emergency_safe_stop"
    assert released["safe_stop_intent"]["controller_generation"] == 1
    assert released["safe_stop_intent"]["lease_token"] == acquired["lease"]["lease_token"]
    state = evolver_controller._read(evolver_controller.state_path(tmp_path))
    assert {event["event_type"] for event in state["audit_events"]} >= {"manual_control_lease_acquired", "manual_control_lease_emergency_release"}


def test_manual_command_is_durable_fenced_and_expires_before_sync_delivery(tmp_path):
    enrolled = _enrolled(tmp_path)
    operator = _operator("operate_run")
    status, lease = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/edge-a/manual-control-lease", {"ttl_seconds": 60},
        operator=operator, state_root=tmp_path,
    )
    assert status == HTTPStatus.CREATED
    status, queued = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/edge-a/manual-command",
        {"operation": "stir_pulse", "duration_ms": 100, "ttl_seconds": 1, "idempotency_key": "pulse-1"},
        operator=operator, state_root=tmp_path,
    )
    assert status == HTTPStatus.ACCEPTED
    command_id = queued["command"]["command_id"]
    state = evolver_controller._read(evolver_controller.state_path(tmp_path))
    command = state["commands"]["edge-a"][0]
    assert command["command_id"] == command_id
    assert command["operation"] == "stir_pulse" and command["expires_at"]
    command["expires_at"] = "2000-01-01T00:00:00Z"
    evolver_controller._write(evolver_controller.state_path(tmp_path), state)
    status, response = evolver_controller.sync(
        {"controller_id": "edge-a", "controller_generation": lease["lease"]["controller_generation"]},
        credential=enrolled["credential"], state_root=tmp_path,
    )
    assert status == HTTPStatus.OK and response["commands"] == []
    status, projection = evolver_controller.dispatch(
        "GET", f"/api/evolver/controllers/edge-a/commands/{command_id}", None, state_root=tmp_path,
    )
    assert status == HTTPStatus.OK
    assert projection["command"]["disposition"] == "expired"
    assert projection["command"]["expiration_reason"] == "ttl_expired"


def test_dedicated_safe_stop_route_is_no_lease_and_preserves_queue_semantics(tmp_path):
    enrolled = _enrolled(tmp_path)
    operator = _operator("operate_run")

    status, queued = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/edge-a/safe-stop",
        {"idempotency_key": "route-safe-stop"}, operator=operator, state_root=tmp_path,
    )

    assert status == HTTPStatus.ACCEPTED
    command = queued["command"]
    assert command["operation"] == "safe_stop"
    assert command["controller_generation"] == enrolled["binding"]["controller_generation"]
    assert command["requested_by"] == "alice"
    assert command["disposition"] == "queued"
    assert command.get("physical_actuation_verified") is None


def test_dedicated_safe_stop_route_allows_foreign_lease_without_using_it(tmp_path):
    _enrolled(tmp_path)
    status, lease = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/edge-a/manual-control-lease", {"ttl_seconds": 60},
        operator=_operator("operate_run"), state_root=tmp_path,
    )
    assert status == HTTPStatus.CREATED
    bob = evolver_controller.OperatorIdentity("bob", "test", frozenset({"operate_run"}))

    status, queued = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/edge-a/safe-stop", {},
        operator=bob, state_root=tmp_path,
    )

    assert status == HTTPStatus.ACCEPTED
    assert queued["command"]["disposition"] == "queued"
    assert queued["command"]["requested_by"] == "bob"
    assert "lease_id" not in queued["command"]
    assert queued["command"].get("lease_token") is None
    assert lease["lease"]["holder"] == "alice"


def test_manual_commands_are_fenced_when_their_lease_is_revoked(tmp_path):
    enrolled = _enrolled(tmp_path)
    operator = _operator("operate_run")
    _, lease = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/manual-control-lease", {"ttl_seconds": 60}, operator=operator, state_root=tmp_path)
    _, queued = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/manual-command", {"operation": "heater_pulse", "duration_ms": 250, "level": 64}, operator=operator, state_root=tmp_path)
    status, _ = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/manual-control-lease/revoke", {}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.OK
    state = evolver_controller._read(evolver_controller.state_path(tmp_path))
    command = next(item for item in state["commands"]["edge-a"] if item["command_id"] == queued["command"]["command_id"])
    assert command["disposition"] == "rejected_lease"
    status, response = evolver_controller.sync({"controller_id": "edge-a", "controller_generation": lease["lease"]["controller_generation"]}, credential=enrolled["credential"], state_root=tmp_path)
    assert status == HTTPStatus.OK and all(item["command_id"] != command["command_id"] for item in response["commands"])


def test_machine_route_dispatch_preserves_persistence_seam_and_lease_methods(tmp_path):
    status, token = evolver_controller.create_enrollment_token(server_url="https://central", state_root=tmp_path)
    assert status == HTTPStatus.CREATED
    status, enrolled = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/enroll",
        {"controller_id": "edge-a", "enrollment_token": token["enrollment_token"]}, state_root=tmp_path,
    )
    assert status == HTTPStatus.CREATED
    status, sync = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/sync",
        {"controller_id": "edge-a", "controller_generation": 1},
        authorization=f"Bearer {enrolled['credential']}", state_root=tmp_path,
    )
    assert status == HTTPStatus.OK and sync["accepted_generation"] == 1
    operator = _operator("operate_run")
    status, _ = evolver_controller.dispatch(
        "PUT", "/api/evolver/controllers/edge-a/manual-control-lease", {}, operator=operator, state_root=tmp_path,
    )
    assert status == HTTPStatus.METHOD_NOT_ALLOWED
    status, invalid = evolver_controller.dispatch(
        "POST", "/api/evolver/controllers/edge-a/manual-command",
        {"operation": "safe_stop", "idempotency_key": 42}, operator=operator, state_root=tmp_path,
    )
    assert status == HTTPStatus.BAD_REQUEST and invalid["kind"] == "BadRequest"


def test_rollback_is_authorized_idempotent_and_generation_fenced(tmp_path):
    _enrolled(tmp_path)
    state_path = evolver_controller.state_path(tmp_path)
    state = evolver_controller._read(state_path)
    state["release_history"].append({"release_id": "r1", "release_kind": "software", "version": "1.0"})
    state["release_deployments"].append({"deployment_id": "d1", "release_id": "r1", "controller_id": "edge-a", "controller_generation": 1})
    state["release_events"].append({"event_id": "e1", "deployment_id": "d1", "event_type": "observed", "controller_generation": 1})
    evolver_controller._write(state_path, state)
    denied, _ = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/rollback", {"release_id": "r1"}, operator=_operator("operate_run"), state_root=tmp_path)
    assert denied == HTTPStatus.FORBIDDEN
    operator = _operator("update_controller")
    status, first = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/rollback", {"release_id": "r1", "idempotency_key": "same"}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.ACCEPTED
    status, second = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/rollback", {"release_id": "r1", "idempotency_key": "same"}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.OK and second["idempotent"] is True
    assert first["rollback_request"]["controller_generation"] == 1


def test_desired_release_uses_validated_catalog_and_keeps_installed_observation_distinct(tmp_path, monkeypatch):
    release_root = tmp_path / "releases"
    (release_root / "2026.08.27").mkdir(parents=True)
    (release_root / "2026.08.27" / "manifest.json").write_text(json.dumps({
        "version": "2026.08.27", "git_revision": "a" * 40, "protocol_version": "1",
        "artifacts": {"linux-x86_64": {"url": "/releases/evolver/2026.08.27/controller.tar.gz", "sha256": "b" * 64, "size": 1}},
    }))
    monkeypatch.setenv("META_WEBUI_EVOLVER_RELEASE_ROOT", str(release_root))
    enrolled = _enrolled(tmp_path)
    status, observation = evolver_controller.sync(
        {"controller_id": "edge-a", "controller_generation": enrolled["binding"]["controller_generation"],
         "heartbeat": {"controller_software_release": "old",
                        "desired_controller_software_release": "stale-intent"}},
        credential=enrolled["credential"], state_root=tmp_path,
    )
    assert status == HTTPStatus.OK and observation["desired_release"] is None
    operator = _operator("update_controller")
    status, response = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/desired-release",
                                                    {"release": "2026.08.27", "idempotency_key": "request-1"},
                                                    operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.ACCEPTED
    assert response["desired_release"] == "2026.08.27" and response["installed_release"] == "old"
    status, catalog = evolver_controller.dispatch("GET", "/api/evolver/releases/catalog", None, state_root=tmp_path)
    assert status == HTTPStatus.OK and catalog["releases"][0]["release"] == "2026.08.27"
    status, duplicate = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/desired-release",
                                                    {"release": "2026.08.27", "idempotency_key": "request-1"},
                                                    operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.OK and duplicate["idempotent"] is True


def test_controller_archive_restore_soft_audits_active_runs(tmp_path):
    _enrolled(tmp_path)
    operator = _operator("manage_controller")
    state_path = evolver_controller.state_path(tmp_path)
    state = evolver_controller._read(state_path)
    state["controllers"]["edge-a"]["recovery_summary"] = {"runs": [{"id": "run-1", "state": "running"}]}
    evolver_controller._write(state_path, state)
    status, archived = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/archive", {}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.OK and archived["controller"]["lifecycle_state"] == "archived"
    assert archived["event"]["active_run_ids"] == ["run-1"]
    status, denied = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/refresh", {}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.CONFLICT and denied["kind"] == "ControllerArchived"
    status, restored = evolver_controller.dispatch("POST", "/api/evolver/controllers/edge-a/restore", {}, operator=operator, state_root=tmp_path)
    assert status == HTTPStatus.OK and restored["controller"]["lifecycle_state"] == "active"
    assert restored["event"]["active_run_ids"] == []
    final = evolver_controller._read(state_path)
    assert [event["event_type"] for event in final["controller_lifecycle_events"]] == ["archived", "restored"]
    assert {event["event_type"] for event in final["audit_events"]} >= {"controller_archived", "controller_active"}
    archived_audit = next(event for event in final["audit_events"] if event["event_type"] == "controller_archived")
    assert archived_audit["details"]["active_run_ids"] == ["run-1"]
