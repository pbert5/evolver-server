"""Bounded experiment action contracts.

The action layer deliberately composes existing bundle and resource machinery.
It does not persist a definition, create a deployment queue entry, or send an
edge command.  Those are control-plane responsibilities and must remain behind
their authoritative API boundaries.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .evolver_controller import resolve_definition_bundle
from .evolver_edge.bundle import BundleResolutionError
from .evolver_run_resources import readiness as resource_readiness

Json = dict[str, Any]


def validate_experiment(
    definition: Mapping[str, Any],
    selected_calibration_artifacts: Sequence[Mapping[str, Any]],
    *,
    resolved_at: str,
) -> Json:
    """Validate and freeze the supplied definition evidence without writing.

    Calibration selection is intentionally an input.  This function does not
    select a latest artifact or consult a catalog, so the caller retains
    policy authority over the evidence included in the immutable bundle.
    """
    try:
        bundle = resolve_definition_bundle(
            definition, selected_calibration_artifacts, resolved_at=resolved_at
        )
    except (BundleResolutionError, TypeError, ValueError) as error:
        return {"valid": False, "errors": [str(error)], "bundle": None}
    return {
        "valid": True,
        "errors": [],
        "bundle": bundle,
        "bundle_id": bundle["id"],
        "bundle_digest": bundle["digest"],
    }


def describe_experiment(value: Mapping[str, Any]) -> Json:
    """Return a stable, credential-free description of a definition or bundle."""
    source = value.get("source")
    resolved_definition = value.get("resolved_definition")
    description: Json = {
        "id": value.get("id"),
        "name": value.get("name"),
        "purpose": value.get("purpose", "research"),
        "schema_version": value.get("schema_version"),
        "execution_mode": value.get("execution_mode"),
        "bundle_digest": value.get("digest"),
        "source": dict(source) if isinstance(source, Mapping) else None,
        "runtime_parameter_count": len(value.get("runtime_parameters", []))
        if isinstance(value.get("runtime_parameters", []), list)
        else 0,
        "calibration_reference_count": len(value.get("calibration_references", []))
        if isinstance(value.get("calibration_references", []), list)
        else 0,
    }
    if isinstance(resolved_definition, Mapping):
        description["definition_snapshot"] = dict(resolved_definition)
    return description


def plan_experiment(
    bundle: Mapping[str, Any],
    *,
    state: Mapping[str, Any] | None = None,
    run_id: str | None = None,
    target_temperature: float | None = None,
    required_capabilities: list[str] | None = None,
) -> Json:
    """Build a side-effect-free preparation/deployment plan.

    When a run and observed edge projection are supplied, readiness is derived
    by the existing resource machinery.  Without them, the plan remains
    blocked until the authoritative control plane has created the run and
    resource assignments.
    """
    blockers: list[str] = []
    readiness: Json | None = None
    if state is None or run_id is None:
        blockers.append("run and assigned resources are not present in the authoritative control plane")
    else:
        try:
            readiness = resource_readiness(
                state,
                run_id,
                target_temperature=target_temperature,
                required_capabilities=required_capabilities,
            )
            blockers.extend(str(item) for item in readiness.get("blockers", []))
            if readiness.get("preheat", {}).get("state") not in {"not_required", "at_target"}:
                blockers.append(
                    f"preheat is {readiness.get('preheat', {}).get('state', 'unknown')}"
                )
        except (KeyError, TypeError, ValueError) as error:
            blockers.append(str(error))
    return {
        "status": "ready" if not blockers else "blocked",
        "bundle_id": bundle.get("id"),
        "bundle_digest": bundle.get("digest"),
        "steps": ["verify_bundle", "verify_resources", "enqueue_deployment", "start_run"],
        "blockers": blockers,
        "readiness": readiness,
        "side_effects": [],
    }


def planned_experiment_action(action: str, **_: Any) -> Json:
    """Describe actions awaiting an authoritative control-plane endpoint.

    Keeping this explicit prevents a local CLI implementation from becoming a
    second queue or scheduler.  The returned gap is part of the operator-facing
    contract and is intentionally precise.
    """
    if action not in {"enqueue", "run"}:
        raise ValueError("planned action must be enqueue or run")
    return {
        "status": "planned",
        "action": action,
        "reason": "unavailable",
        "gap": (
            "no authoritative control-plane API is exposed here to persist a "
            "DeploymentQueueEntry/run intent, apply generation and revision "
            "fencing, and deliver the resulting command to edge"
        ),
        "side_effects": [],
    }
