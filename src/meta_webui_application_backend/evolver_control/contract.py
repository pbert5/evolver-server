"""Read-only projection of the canonical operator action catalog.

The catalog is data, never executable code.  This module only resolves a
validated method/path to a stable action id; trusted Python adapters remain in
``actions.py``.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping

from .actions import ACTION_ADAPTERS


def catalog_path() -> Path:
    configured = __import__("os").environ.get("EVOLVER_ACTION_CATALOG")
    if configured:
        return Path(configured)
    relative_catalog = Path("metactl") / "applications" / "evolver" / "actions.json"
    source_path = Path(__file__).resolve()
    for checkout_root in source_path.parents:
        candidate = checkout_root / relative_catalog
        if candidate.is_file():
            return candidate
    # Keep the failure actionable if a packaged/standalone checkout omitted
    # the canonical catalog.  The explicit environment override above is the
    # supported deployment escape hatch for that layout.
    return source_path.parents[3] / relative_catalog


def operator_actions() -> dict[str, dict[str, Any]]:
    document = json.loads(catalog_path().read_text(encoding="utf-8"))
    actions = {item["id"]: item for item in document.get("actions", [])}
    result = {}
    for action_id, binding in document.get("api", {}).items():
        if action_id not in actions or not isinstance(binding, Mapping):
            raise ValueError(f"invalid operator action contract: {action_id}")
        result[action_id] = {**actions[action_id], "api": dict(binding)}
    return result


def manifest() -> dict[str, Any]:
    return {"version": json.loads(catalog_path().read_text(encoding="utf-8")).get("version"),
            "actions": [{"id": action_id, "title": action["title"], "method": action["api"]["method"],
                         "path": action["api"]["path"], "permissions": list(action.get("permissions", [])),
                         "safety": action.get("safety", {})}
                        for action_id, action in operator_actions().items()]}


def match(method: str, path: str, requested_action: str | None = None) -> tuple[str, dict[str, str]] | None:
    for action_id, action in operator_actions().items():
        binding = action["api"]
        if binding["method"] != method:
            continue
        if requested_action and action_id.rsplit(".", 1)[-1] != requested_action:
            continue
        names = re.findall(r"\{([^{}]+)\}", binding["path"])
        expression = re.escape(binding["path"])
        for name in names:
            expression = expression.replace("\\{" + re.escape(name) + "\\}", rf"(?P<{name}>[^/]+)")
        found = re.fullmatch(expression, path)
        if found:
            return action_id, found.groupdict()
    return None


def validate_parameters(action_id: str, parameters: Mapping[str, Any]) -> str | None:
    action = operator_actions()[action_id]
    declared = action.get("parameters", {})
    unknown = set(parameters) - set(declared) - {"action"}
    if unknown:
        return f"unexpected parameters: {sorted(unknown)}"
    for name, spec in declared.items():
        if spec.get("required") is True and name not in parameters:
            return f"missing required parameter: {name}"
        if name not in parameters:
            continue
        value = parameters[name]
        kind = spec["type"]
        valid = {"string": isinstance(value, str), "integer": isinstance(value, int) and not isinstance(value, bool),
                 "number": isinstance(value, (int, float)) and not isinstance(value, bool),
                 "boolean": isinstance(value, bool), "object": isinstance(value, dict),
                 "array": isinstance(value, list), "json": True}[kind]
        if not valid:
            return f"parameter {name} must be a {kind}"
        if "enum" in spec and value not in spec["enum"]:
            return f"parameter {name} is not a supported value"
    return None


def validate_runtime_contract() -> None:
    actions = operator_actions()
    adapters = set(ACTION_ADAPTERS)
    missing = set(actions) - adapters
    if missing:
        raise ValueError(f"operator actions without trusted adapters: {sorted(missing)}")
