from __future__ import annotations

from pathlib import Path
import re

from meta_webui_application_backend.database.migrations import configured_migrations


def test_server_default_config_is_self_contained_and_central_only(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    migrations = configured_migrations()
    assert [migration.identifier for migration in migrations] == [
        "0011_evolver_central_controller", "0013_evolver_calibration_control_plane",
        "0016_evolver_release_history", "0017_evolver_run_resources",
        "0018_evolver_control_plane_operations", "0019_evolver_lease_token",
        "0020_evolver_controller_lifecycle", "0021_evolver_command_delivery_projection",
        "0022_evolver_command_delivery_eligibility", "0023_evolver_calibration_evidence",
        "0024_evolver_component_calibration_targets", "0025_runtime_provenance",
        "0026_evolver_normalized_history",
    ]
    assert all(migration.path.is_relative_to(Path(__file__).parents[1]) for migration in migrations)
    assert all("core." not in migration.sql for migration in migrations)


def test_server_migrations_cover_central_store_relations() -> None:
    root = Path(__file__).parents[1]
    sql = "\n".join(migration.sql for migration in configured_migrations(root, {}))
    central_store = (root / "src/meta_webui_application_backend/central_store.py").read_text(encoding="utf-8")
    relations = set(re.findall(r"evolver\.([a-z_]+)", central_store))
    assert all(f"evolver.{relation}" in sql for relation in relations)
    assert "CREATE SCHEMA IF NOT EXISTS evolver" in sql
    assert "ADD COLUMN IF NOT EXISTS delivery_eligible" in sql
    assert "controller_event_history" in sql
    assert "controller_telemetry_history" in sql
    assert "reject_history_mutation" in sql
