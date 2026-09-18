"""Validated, packaged operator action contract and deterministic export."""
from __future__ import annotations

import json
import os
import re
from importlib.resources import files
from typing import Any, Mapping

from .actions import ACTION_ADAPTERS

_RESOURCE = "evolver_server/contracts/operator_actions.json"


def catalog_source() -> str:
    return _RESOURCE


def _document() -> dict[str, Any]:
    if os.environ.get("EVOLVER_ACTION_CATALOG"):
        raise ValueError("EVOLVER_ACTION_CATALOG override is unsupported")
    try:
        raw = files("evolver_server").joinpath("contracts/operator_actions.json").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise ValueError("packaged operator action contract is unavailable") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("packaged operator action contract is malformed") from exc
    if not isinstance(document, dict) or not isinstance(document.get("actions"), list):
        raise ValueError("packaged operator action contract has invalid shape")
    if not isinstance(document.get("revision"), str) or not document["revision"]:
        raise ValueError("packaged operator action contract has no revision")
    if not isinstance(document.get("api", {}), dict):
        raise ValueError("packaged operator action contract has invalid api shape")
    for item in document["actions"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("title"), str):
            raise ValueError("packaged operator action contract has invalid action shape")
        if item.get("status") not in {"implemented", "planned"}:
            raise ValueError(f"invalid operator action status: {item.get('id')}")
        if not isinstance(item.get("permissions", []), list) or not isinstance(item.get("safety", {}), dict):
            raise ValueError(f"invalid operator action metadata: {item['id']}")
    return document


def catalog_document() -> dict[str, Any]:
    return _document()


def _callable_actions(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    actions = {item["id"]: item for item in document["actions"] if item.get("status") == "implemented"}
    result = {}
    for action_id, binding in document.get("api", {}).items():
        if action_id not in actions or not isinstance(binding, Mapping):
            raise ValueError(f"invalid operator action contract: {action_id}")
        result[action_id] = {**actions[action_id], "api": dict(binding), "callable": True}
    if set(result) != set(actions):
        raise ValueError("implemented operator actions and api bindings differ")
    return result


def operator_actions() -> dict[str, dict[str, Any]]:
    return _callable_actions(_document())


def required_permission(action_id: str) -> str | None:
    permissions = operator_actions()[action_id].get("permissions", [])
    if not permissions:
        return None
    return {"evolver:read": "view"}.get(permissions[0], permissions[0])


def manifest() -> dict[str, Any]:
    document = _document()
    callable_actions = _callable_actions(document)
    actions = []
    for item in document["actions"]:
        action_id = item["id"]
        binding = callable_actions.get(action_id, {}).get("api")
        actions.append({
            "id": action_id,
            "title": item["title"],
            "status": item["status"],
            "callable": binding is not None,
            "method": binding.get("method") if binding else None,
            "path": binding.get("path") if binding else None,
            "permissions": list(item.get("permissions", [])),
            "safety": item.get("safety", {}),
        })
    return {"version": document["version"], "revision": document["revision"], "actions": actions}


def export_contract() -> str:
    """Serialize the packaged contract canonically for downstream snapshots."""
    return json.dumps(_document(), sort_keys=True, separators=(",", ":")) + "\n"


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
    extra = adapters - set(actions)
    if missing:
        raise ValueError(f"operator actions without trusted adapters: {sorted(missing)}")
    if extra:
        raise ValueError(f"trusted adapters without operator actions: {sorted(extra)}")


if __name__ == "__main__":
    print(export_contract(), end="")
