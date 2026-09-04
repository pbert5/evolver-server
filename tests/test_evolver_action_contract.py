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
