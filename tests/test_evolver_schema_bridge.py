from pathlib import Path
import sys

from meta_webui_application_backend.evolver_controller import resolve_definition_bundle


SCHEMA_TOOLS = Path(__file__).parents[2] / "evolver-schemas" / "tools"
sys.path.insert(0, str(SCHEMA_TOOLS))
from compiler import compile_definition  # noqa: E402


def test_server_resolves_schema_compiler_bundle_for_edge_execution():
    compiled = compile_definition({
        "id": "schema-run", "purpose": "research",
        "program": {
            "version": "1", "entry_step_id": "start", "steps": [{"id": "start"}],
            "completion_policy": {"mode": "all_steps"},
            "failure_policy": {"mode": "stop_run"},
        },
    })
    definition = {
        "id": "definition-1", "name": "schema run", "dataset_id": "dataset-1",
        "dataset_revision": "rev-1",
        "definition": {"media_type": "application/json", "content": compiled},
    }

    bundle = resolve_definition_bundle(definition, [], resolved_at="2026-09-04T00:00:00Z")

    assert bundle["execution_plan"]["initial_state"] == "start"
    assert bundle["action_registry_revision"] == "trusted-actions-1"
    assert bundle["digest"]
