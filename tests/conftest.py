"""Shared endpoint configuration for server tests.

The production registry is intentionally empty until a deployment supplies a
verified controller-reachable endpoint.  These are test-only fixtures matching
the endpoint values already exercised by the server contract tests.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def approved_enrollment_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "META_WEBUI_EVOLVER_CONTROLLER_ENDPOINTS",
        '[{"id":"central","label":"Central","url":"https://central",'
        '"controller_reachable":true,"enabled":true},'
        '{"id":"webui-example","label":"WebUI example",'
        '"url":"https://webui.example","controller_reachable":true,"enabled":true}]',
    )
