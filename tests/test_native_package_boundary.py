from __future__ import annotations

import importlib
from pathlib import Path


ROOT = Path(__file__).parents[1]
SRC = ROOT / "src"


def test_server_exposes_native_experiment_bundle() -> None:
    bundle = importlib.import_module("evolver_server.experiments.bundle")

    assert bundle.resolve_bundle
    assert bundle.BundleResolutionError


def test_server_source_contains_no_copied_edge_runtime() -> None:
    assert not (SRC / "meta_webui_application_backend").exists()
    assert not (SRC / "evolver_server" / "evolver_edge").exists()


def test_server_entrypoint_targets_native_service() -> None:
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'evolver-control = "evolver_server.control.service:main"' in metadata
