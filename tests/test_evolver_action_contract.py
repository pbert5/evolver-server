from __future__ import annotations

import json
import re

from evolver_server.control import contract
from evolver_server.control.actions import ACTION_ADAPTERS, UnknownAction, dispatch


def test_catalog_exposure_matches_trusted_server_adapters():
    exposed = set(contract.operator_actions())
    assert exposed <= set(ACTION_ADAPTERS)
    contract.validate_runtime_contract()


def test_catalog_is_loaded_from_the_server_package(monkeypatch):
    monkeypatch.chdir("/")
    monkeypatch.delenv("EVOLVER_ACTION_CATALOG", raising=False)
    document = contract.catalog_document()
    assert document["version"] == "1.0.0"
    assert document["revision"] == "operator-actions-1"
    assert contract.catalog_source() == "evolver_server/contracts/operator_actions.json"


def test_catalog_rejects_checkout_override_and_exports_deterministically(tmp_path, monkeypatch):
    monkeypatch.setenv("EVOLVER_ACTION_CATALOG", str(tmp_path / "actions.json"))
    with __import__("pytest").raises(ValueError, match="unsupported"):
        contract.catalog_document()
    monkeypatch.delenv("EVOLVER_ACTION_CATALOG")
    exported = contract.export_contract()
    assert exported == contract.export_contract()
    assert json.loads(exported)["revision"] == "operator-actions-1"


def test_missing_and_malformed_packaged_contracts_fail_closed(monkeypatch):
    class Missing:
        def joinpath(self, _name):
            return self

        def read_text(self, **_kwargs):
            raise FileNotFoundError("missing")

    monkeypatch.setattr(contract, "files", lambda _package: Missing())
    with __import__("pytest").raises(ValueError, match="unavailable"):
        contract.catalog_document()

    class Malformed(Missing):
        def read_text(self, **_kwargs):
            return "{"

    monkeypatch.setattr(contract, "files", lambda _package: Malformed())
    with __import__("pytest").raises(ValueError, match="malformed"):
        contract.catalog_document()

    class InvalidShape(Missing):
        def read_text(self, **_kwargs):
            return json.dumps({"revision": "r1", "actions": [{}], "api": {}})

    monkeypatch.setattr(contract, "files", lambda _package: InvalidShape())
    with __import__("pytest").raises(ValueError, match="invalid action shape"):
        contract.catalog_document()


def test_planned_actions_are_discoverable_but_not_callable():
    planned = [item for item in contract.catalog_document()["actions"] if item["status"] == "planned"]
    assert planned
    assert all(item["id"] not in contract.operator_actions() for item in planned)
    assert all(item["callable"] is False for item in contract.manifest()["actions"] if item["status"] == "planned")
    with __import__("pytest").raises(UnknownAction):
        dispatch("evolver.experiments.enqueue")


def test_callable_metadata_has_permission_and_safety_contract():
    for item in contract.manifest()["actions"]:
        assert isinstance(item["permissions"], list)
        assert set(item["safety"]) >= {"risk", "confirmation", "reversible"}
        if item["callable"]:
            assert item["method"] in {"GET", "POST", "PATCH", "DELETE"}
            assert isinstance(item["path"], str)


def test_projection_is_deterministic_and_extracts_path_parameters():
    assert contract.match("GET", "/api/evolver/controllers/edge-a") == (
        "evolver.controllers.show", {"controller_id": "edge-a"})
    assert contract.match("POST", "/api/evolver/runs/run-a/commands", "pause")[0] == "evolver.runs.pause"


def test_parameter_contract_rejects_missing_and_unknown_fields():
    assert contract.validate_parameters("evolver.controllers.show", {}) == "missing required parameter: controller_id"
    assert contract.validate_parameters("evolver.controllers.show", {"controller_id": "a", "extra": 1}) == "unexpected parameters: ['extra']"


def test_every_catalog_api_action_has_an_exact_route_binding():
    """Keep the published route/action surface complete and executable."""
    for action_id, action in contract.operator_actions().items():
        binding = action["api"]
        requested = action_id.rsplit(".", 1)[-1]
        parameters = {
            name: f"example-{name}" for name in re.findall(r"\{([^{}]+)\}", binding["path"])
        }
        concrete_path = binding["path"]
        for name, value in parameters.items():
            concrete_path = concrete_path.replace("{" + name + "}", value)
        assert contract.match(binding["method"], concrete_path, requested) == (action_id, parameters)
        assert action_id in ACTION_ADAPTERS


def test_route_action_and_parameter_validation_rejects_ambiguous_requests():
    assert contract.match("POST", "/api/evolver/runs/run-a/commands", "stop") == (
        "evolver.runs.stop", {"run_id": "run-a"}
    )
    assert contract.match("POST", "/api/evolver/runs/run-a/commands", "delete") is None

    action = "evolver.runs.pause"
    assert contract.validate_parameters(action, {"run_id": "run-a"}) == "missing required parameter: expected_revision"
    assert contract.validate_parameters(action, {"run_id": "run-a", "expected_revision": True}) == (
        "parameter expected_revision must be a integer"
    )
    assert contract.validate_parameters(action, {
        "run_id": "run-a", "expected_revision": 3, "unexpected": "value"
    }) == "unexpected parameters: ['unexpected']"
