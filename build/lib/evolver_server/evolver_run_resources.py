"""Central run/resource lifecycle facts.

This module only records future intent and observed readiness.  It never sends
hardware commands.  Assignment transitions are append-only; the latest fact
for a resource is the active projection and the complete list is the audit
history.
"""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


RESOURCE_KINDS = frozenset({"instrument", "vial_position", "pump"})
ACTIVE_STATES = frozenset({"assigned"})
CAPABILITY_VERIFICATION = frozenset({"protocol_verified", "physically_verified"})


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise ValueError("expires_at must be an ISO timestamp") from None


def _run(state: Mapping[str, Any], run_id: str) -> tuple[str, dict[str, Any]] | None:
    for controller_id, controller in state.get("controllers", {}).items():
        if not isinstance(controller, Mapping):
            continue
        summary = controller.get("recovery_summary") or controller.get("recovery_manifest") or {}
        for run in summary.get("runs", []) if isinstance(summary, Mapping) else []:
            if isinstance(run, dict) and run.get("id") == run_id:
                return str(controller_id), run
    return None


def _inventory(state: Mapping[str, Any], resource_id: str) -> tuple[str, dict[str, Any]] | None:
    for controller_id, controller in state.get("controllers", {}).items():
        if not isinstance(controller, Mapping):
            continue
        for instrument in controller.get("inventory", []):
            if isinstance(instrument, dict) and instrument.get("id") == resource_id:
                return str(controller_id), instrument
            if isinstance(instrument, dict):
                for vial in instrument.get("vial_positions", []):
                    vial_id = vial.get("id") if isinstance(vial, Mapping) else vial
                    if vial_id == resource_id:
                        return str(controller_id), instrument
                for device in instrument.get("devices", []):
                    if isinstance(device, Mapping) and device.get("id") == resource_id:
                        return str(controller_id), instrument
    return None


def _active(state: Mapping[str, Any], run_id: str) -> list[dict[str, Any]]:
    latest: dict[tuple[str, str], dict[str, Any]] = {}
    for item in state.get("run_resource_assignments", []):
        if isinstance(item, dict) and item.get("run_id") == run_id:
            key = (str(item.get("resource_kind")), str(item.get("resource_id")))
            if item.get("assignment_state") in {"assigned", "released", "replaced"}:
                latest[key] = item
    return [copy.deepcopy(item) for item in latest.values() if item.get("assignment_state") == "assigned"]


def _capability_ready(instrument: Mapping[str, Any], required: list[str]) -> tuple[bool, list[str]]:
    capabilities = instrument.get("capabilities", {})
    if not isinstance(capabilities, Mapping):
        capabilities = {}
    blockers = []
    for name in required:
        detail = capabilities.get(name)
        if not isinstance(detail, Mapping) or detail.get("enabled", True) is False:
            blockers.append(f"missing capability: {name}")
        elif detail.get("verification") not in CAPABILITY_VERIFICATION:
            blockers.append(f"capability not verified: {name}")
    if instrument.get("connection_state") not in {None, "connected"}:
        blockers.append("instrument is not connected")
    return not blockers, blockers


def readiness(state: Mapping[str, Any], run_id: str, *, target_temperature: float | None = None,
              tolerance: float = 0.5, required_capabilities: list[str] | None = None) -> dict[str, Any]:
    required = required_capabilities or []
    blockers: list[str] = []
    resources = _active(state, run_id)
    for assignment in resources:
        if _time(assignment.get("expires_at")) <= datetime.now(timezone.utc):
            blockers.append(f"resource assignment expired: {assignment['resource_id']}")
        found = _inventory(state, str(assignment["resource_id"]))
        if found is None:
            blockers.append(f"resource unavailable: {assignment['resource_id']}")
            continue
        _, instrument = found
        ready, reasons = _capability_ready(instrument, required)
        if not ready:
            blockers.extend(reasons)
    preheat = {"state": "not_required", "target_temperature": target_temperature,
               "tolerance": tolerance, "observed_temperature": None}
    if target_temperature is not None:
        temperatures = []
        for controller in state.get("controllers", {}).values():
            if not isinstance(controller, Mapping):
                continue
            for record in controller.get("telemetry", []):
                if not isinstance(record, Mapping) or record.get("run_id") != run_id:
                    continue
                value = record.get("temperature_c")
                if not isinstance(value, (int, float)) and isinstance(record.get("payload"), Mapping):
                    value = record["payload"].get("temperature_c")
                if isinstance(value, (int, float)):
                    temperatures.append(float(value))
        if temperatures:
            current = temperatures[-1]
            preheat["observed_temperature"] = current
            preheat["state"] = "at_target" if abs(current - target_temperature) <= tolerance else "heating"
        else:
            preheat["state"] = "pending"
    return {"state": "ready" if not blockers and preheat["state"] in {"not_required", "at_target"} else "blocked",
            "blockers": blockers, "preheat": preheat, "active_assignments": resources}


def add(state: dict[str, Any], run_id: str, body: Mapping[str, Any], *, actor: str) -> dict[str, Any]:
    found = _run(state, run_id)
    if found is None:
        raise KeyError("run not found")
    kind, resource_id = body.get("resource_kind"), body.get("resource_id")
    if kind not in RESOURCE_KINDS or not isinstance(resource_id, str) or not resource_id:
        raise ValueError("resource_kind and resource_id are required")
    expires = body.get("expires_at") or body.get("valid_until")
    if not isinstance(expires, str) or _time(expires) <= _time(now()):
        raise ValueError("a future expires_at is required")
    request_id = body.get("request_id")
    all_items = state.setdefault("run_resource_assignments", [])
    if request_id:
        prior = next((x for x in all_items if isinstance(x, dict) and x.get("request_id") == request_id), None)
        if prior is not None:
            return copy.deepcopy(prior)
    supersedes_id = body.get("replaces_assignment_id")
    if supersedes_id is not None:
        if not isinstance(supersedes_id, str) or not any(
            item.get("id") == supersedes_id and item.get("run_id") == run_id
            and item.get("assignment_state") in {"released", "replaced"}
            for item in all_items if isinstance(item, Mapping)
        ):
            raise ValueError("replaces_assignment_id must identify a released or replaced assignment")
    inventory = _inventory(state, resource_id)
    if inventory is None:
        raise ValueError("resource is not present in observed inventory")
    controller_id, instrument = inventory
    if controller_id != found[0]:
        raise ValueError("resource belongs to a different controller")
    if kind == "instrument" and resource_id not in (found[1].get("instrument_ids") or []):
        raise ValueError("instrument is not part of this run")
    if kind == "vial_position" and resource_id not in [v.get("id") if isinstance(v, Mapping) else v for v in instrument.get("vial_positions", [])]:
        raise ValueError("vial position is not present in observed inventory")
    if any(x.get("resource_kind") == kind and x.get("resource_id") == resource_id for x in _active(state, run_id)):
        raise ValueError("resource is already assigned to this run")
    if kind == "vial_position":
        sample = body.get("sample_reference")
        if not isinstance(sample, Mapping) or not all(isinstance(sample.get(k), str) and sample[k] for k in ("sample_barcode", "bal_schema_version", "source_record_id")):
            raise ValueError("vial assignments require a BAL sample_reference")
    sequence = max([int(x.get("sequence", 0)) for x in all_items if isinstance(x, dict) and x.get("run_id") == run_id] or [0]) + 1
    item = {"id": f"run-resource-{uuid.uuid4()}", "run_id": run_id, "sequence": sequence,
            "resource_kind": kind, "resource_id": resource_id, "assignment_state": "assigned",
            "assigned_at": now(), "expires_at": expires, "assigned_by": actor,
            "request_id": request_id, "supersedes_id": supersedes_id,
            "required_capabilities": list(body.get("required_capabilities", [])),
            "sample_reference": copy.deepcopy(body.get("sample_reference")) if kind == "vial_position" else None,
            "target_temperature": body.get("target_temperature"), "tolerance": body.get("tolerance", 0.5)}
    all_items.append(item)
    state.setdefault("run_resource_events", []).append({"id": f"run-resource-event-{uuid.uuid4()}", "event_type": "assigned", "run_id": run_id, "assignment_id": item["id"], "occurred_at": item["assigned_at"], "actor": actor})
    return copy.deepcopy(item)


def transition(state: dict[str, Any], run_id: str, assignment_id: str, action: str, *, actor: str, reason: str | None = None) -> dict[str, Any]:
    current = next((x for x in reversed(state.get("run_resource_assignments", [])) if isinstance(x, dict) and x.get("run_id") == run_id and x.get("id") == assignment_id and x.get("assignment_state") == "assigned"), None)
    if current is None:
        raise KeyError("active assignment not found")
    if action not in {"release", "replace"}:
        raise ValueError("unsupported assignment transition")
    new_state = "released" if action == "release" else "replaced"
    item = copy.deepcopy(current)
    item.update({"id": f"run-resource-{uuid.uuid4()}", "sequence": max([int(x.get("sequence", 0)) for x in state["run_resource_assignments"] if isinstance(x, dict) and x.get("run_id") == run_id] or [0]) + 1,
                 "assignment_state": new_state, "assigned_at": now(), "released_at": now(), "assigned_by": actor, "reason": reason, "supersedes_id": assignment_id})
    state["run_resource_assignments"].append(item)
    state.setdefault("run_resource_events", []).append({"id": f"run-resource-event-{uuid.uuid4()}", "event_type": new_state, "run_id": run_id, "assignment_id": assignment_id, "occurred_at": item["released_at"], "actor": actor, "reason": reason})
    return item
