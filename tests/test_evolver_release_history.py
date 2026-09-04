from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from meta_webui_application_backend.evolver_release_history import (
    Deployment,
    Release,
    ReleaseHistoryError,
    manifest_digest,
    rollback_eligibility,
    validate_deployment,
    validate_release,
)


def _release(release_id: str, version: str) -> dict[str, object]:
    return {"release_id": release_id, "release_kind": "software", "version": version}


def test_manifest_digest_is_canonical() -> None:
    manifest = {"version": "r1", "artifacts": {"linux-x86_64": {"sha256": "a"}}}
    expected = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert manifest_digest({"artifacts": manifest["artifacts"], "version": "r1"}) == expected


def test_release_requires_matching_immutable_manifest_digest() -> None:
    release = Release("r1", "software", "1.0", "abc", "0" * 64, {"version": "r1"}, "2026-08-26T00:00:00Z", "alice")
    with pytest.raises(ReleaseHistoryError, match="does not match"):
        validate_release(release)


def test_rollback_requires_observed_fact_and_generation_fencing() -> None:
    releases = [_release("r1", "1.0"), _release("r2", "2.0"), _release("r3", "3.0")]
    deployments = [
        {"deployment_id": "d1", "release_id": "r1", "controller_id": "c1", "controller_generation": 7},
        {"deployment_id": "d2", "release_id": "r2", "controller_id": "c1", "controller_generation": 7},
        {"deployment_id": "d3", "release_id": "r3", "controller_id": "c1", "controller_generation": 6},
    ]
    events = [
        {"deployment_id": "d1", "event_type": "ack_received", "controller_generation": 7},
        {"deployment_id": "d2", "event_type": "observed", "controller_generation": 7},
        {"deployment_id": "d3", "event_type": "observed", "controller_generation": 6},
    ]
    result = rollback_eligibility("r3", releases, deployments, events, controller_id="c1", controller_generation=7)
    assert result["eligible"] is True
    assert [item["release_id"] for item in result["candidates"]] == ["r2"]


def test_ack_is_not_physical_observation() -> None:
    result = rollback_eligibility("r2", [_release("r1", "1.0"), _release("r2", "2.0")],
                                  [{"deployment_id": "d1", "release_id": "r1", "controller_id": "c1", "controller_generation": 1}],
                                  [{"deployment_id": "d1", "event_type": "ack_received", "controller_generation": 1}],
                                  controller_id="c1", controller_generation=1)
    assert result["eligible"] is False


def test_rollback_candidate_requires_registered_release() -> None:
    result = rollback_eligibility("missing", [], [], [], controller_id="c1", controller_generation=1)
    assert result["eligible"] is False and result["candidates"] == []


def test_migration_is_append_only_and_configured() -> None:
    migration = Path("applications/deployment/databases/postgres/migrations/0016_evolver_release_history.sql").read_text()
    assert "BEFORE UPDATE OR DELETE" in migration
    assert "ON CONFLICT" not in migration.split("CREATE FUNCTION", 1)[0]  # no upsert/update path for history
    assert migration.endswith("\n")


def test_deployment_requires_operator_attribution_and_positive_generation() -> None:
    with pytest.raises(ReleaseHistoryError, match="controller_generation"):
        validate_deployment(Deployment("d", "r", "c", 0, "cmd", "alice", "session", "now"))
