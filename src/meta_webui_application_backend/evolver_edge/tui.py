"""Local eVOLVER Textual entrypoint over the same configured page documents."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from config_compiler import compile_application
from meta_webui_ui_runtime_textual import ApplicationLoader

from .store import EdgeStore


_LOCAL_QUERY_PAGES = {
    "overview": "evolver_overview",
    "controllers": "evolver_controllers",
    "instruments": "evolver_instruments",
    "runs": "evolver_runs",
    "recovery": "evolver_recovery",
    "maintenance": "evolver_maintenance",
}


def _application_root() -> Path:
    configured = os.environ.get("META_WEBUI_APPLICATION_ROOT")
    candidates = [Path(configured)] if configured else []
    candidates.extend((Path.cwd() / "applications" / "deployment", Path("/etc/meta-webui/applications/deployment")))
    return next((candidate for candidate in candidates if (candidate / "app.yaml").is_file()), candidates[0] if candidates else Path("applications/deployment"))


def _local_source(store: EdgeStore):
    """Offline adapter: the central API is never needed for edge-local views."""
    def resolve(source: Mapping[str, Any], _scope: Mapping[str, Any]) -> Any:
        query = source.get("query")
        if query == "evolver.controllers":
            binding = store.binding()
            return [{**store.identity(), "binding": binding, "connection_state": "local_edge", "inventory": store.list_instruments()}]
        if query == "evolver.controller_snapshot":
            return {"controller": store.identity(), "binding": store.binding(), "instruments": store.list_instruments(), "central": "offline"}
        if query == "evolver.runs":
            return store.list_runs()
        if query == "evolver.instruments":
            return store.list_instruments()
        if query == "evolver.maintenance":
            return [{"controller_id": store.identity()["id"], "connection_state": "local_edge",
                     "binding": store.binding(), "software_release": store.meta("controller_software_release"),
                     "desired_release": store.meta("desired_controller_software_release"),
                     "update_policy": os.environ.get("EVOLVER_UPDATE_POLICY", "when_idle"),
                     "service_health": "local_edge", "hardware_service_health": "unknown"}]
        return None
    return resolve


def run(store: EdgeStore, *, page: str = "overview") -> int:
    """Run the configured local operator TUI.

    The source adapter uses EdgeStore only.  Consequently it remains useful
    during a central outage; reconnecting central does not replace or mutate
    local state from the TUI.
    """
    page_id = _LOCAL_QUERY_PAGES.get(page, page)
    document = compile_application(_application_root()).app_config["definition"]
    app = ApplicationLoader(document, source_resolver=_local_source(store)).application(page_id, scope={"edge": {"status": "CENTRAL OFFLINE · EDGE RUNNING"}})
    app.run()
    return 0
