from __future__ import annotations

from meta_webui_application_backend.evolver_control import contract
from meta_webui_application_backend.evolver_control.actions import ACTION_ADAPTERS


def test_catalog_exposure_matches_trusted_server_adapters():
    exposed = set(contract.operator_actions())
    assert exposed <= set(ACTION_ADAPTERS)
    contract.validate_runtime_contract()


def test_projection_is_deterministic_and_extracts_path_parameters():
    assert contract.match("GET", "/api/evolver/controllers/edge-a") == (
        "evolver.controllers.show", {"controller_id": "edge-a"})
    assert contract.match("POST", "/api/evolver/runs/run-a/commands", "pause")[0] == "evolver.runs.pause"


def test_parameter_contract_rejects_missing_and_unknown_fields():
    assert contract.validate_parameters("evolver.controllers.show", {}) == "missing required parameter: controller_id"
    assert contract.validate_parameters("evolver.controllers.show", {"controller_id": "a", "extra": 1}) == "unexpected parameters: ['extra']"


def test_every_catalog_api_action_has_an_exact_route_binding():
    """Keep the published route/action surface complete and executable."""
    import re

    for action_id, action in contract.operator_actions().items():
        binding = action["api"]
        requested = action_id.rsplit(".", 1)[-1]
        assert contract.match(binding["method"], binding["path"], requested) == (action_id, {
            name: f"example-{name}" for name in re.findall(r"\{([^{}]+)\}", binding["path"])
        })
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
