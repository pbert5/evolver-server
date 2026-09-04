"""Pure central-side resolution of immutable experiment bundles.

This module has no filesystem, database, controller, or hardware dependency.
The edge imports only its wire-level validation helpers; bundle construction
remains a central Definition -> Bundle concern.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

Json = dict[str, Any]
EXPERIMENT_PURPOSES = frozenset({"research", "test_fixture", "commissioning"})


class BundleResolutionError(ValueError):
    """A definition-side bundle cannot be frozen from the supplied evidence."""


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def calibration_artifact_digest(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("artifact_digest", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


CALIBRATION_TARGET_FIELDS = ("instrument_id", "vial_position_id", "component_id", "calibration_type")
CALIBRATION_ARTIFACT_FIELDS = ("id", "artifact_digest", *CALIBRATION_TARGET_FIELDS, "method", "method_version")
CALIBRATION_REQUIREMENT_FIELDS = ("capability", *CALIBRATION_TARGET_FIELDS, "required")


def normalize_calibration_requirement(value: Any, index: int, *, error_type: type[Exception] = BundleResolutionError) -> Json:
    if not isinstance(value, Mapping):
        raise error_type(f"calibration requirement[{index}] is not an object")
    item = dict(value)
    required = item.get("required")
    if not isinstance(required, bool):
        raise error_type(f"calibration requirement[{index}] must declare required as true or false")
    for field in ("capability", "instrument_id", "vial_position_id", "calibration_type"):
        if not isinstance(item.get(field), str) or not item[field]:
            raise error_type(f"calibration requirement[{index}] lacks capability or target identity")
    component = item.get("component_id")
    if component is not None and (not isinstance(component, str) or not component):
        raise error_type(f"calibration requirement[{index}] has an invalid component identity")
    return {field: item.get(field) for field in CALIBRATION_REQUIREMENT_FIELDS}


def calibration_requirement_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(value.get(field) for field in ("capability", *CALIBRATION_TARGET_FIELDS))


def resolve_bundle(bundle: Mapping[str, Any], calibration_artifacts: Any) -> Json:
    """Freeze caller-selected calibration evidence into an immutable bundle."""
    payload = dict(bundle)
    if "digest" in payload:
        raise BundleResolutionError("resolve a bundle before supplying its digest")
    requirements = payload.get("calibration_requirements", [])
    if not isinstance(requirements, list):
        raise BundleResolutionError("calibration_requirements must be a list")
    normalized = [normalize_calibration_requirement(item, index) for index, item in enumerate(requirements)]
    keys = [calibration_requirement_key(item) for item in normalized]
    if len(keys) != len(set(keys)):
        raise BundleResolutionError("calibration requirements must not duplicate a capability target")
    if not isinstance(calibration_artifacts, (list, tuple)):
        raise BundleResolutionError("calibration artifacts must be a finite selected list")
    artifacts: list[Json] = []
    ids: set[str] = set()
    for index, value in enumerate(calibration_artifacts):
        if not isinstance(value, Mapping):
            raise BundleResolutionError(f"calibration artifact[{index}] is not an object")
        artifact = dict(value)
        if any(not isinstance(artifact.get(field), str) or not artifact[field]
               for field in CALIBRATION_ARTIFACT_FIELDS if field != "component_id"):
            raise BundleResolutionError(f"calibration artifact[{index}] lacks immutable identity")
        component = artifact.get("component_id")
        if component is not None and (not isinstance(component, str) or not component):
            raise BundleResolutionError(f"calibration artifact[{index}] has an invalid component identity")
        if artifact["id"] in ids:
            raise BundleResolutionError(f"calibration artifact[{index}] duplicates {artifact['id']}")
        ids.add(artifact["id"])
        if artifact["artifact_digest"] != calibration_artifact_digest(artifact):
            raise BundleResolutionError(f"calibration artifact[{index}] digest does not match canonical content")
        artifacts.append(artifact)
    references: list[Json] = []
    for requirement in normalized:
        matches = [artifact for artifact in artifacts
                   if all(artifact.get(field) == requirement.get(field) for field in CALIBRATION_TARGET_FIELDS)]
        if len(matches) > 1:
            raise BundleResolutionError(f"calibration selection is ambiguous for {requirement['capability']}")
        if not matches:
            if requirement["required"]:
                raise BundleResolutionError(f"required calibration is missing for {requirement['capability']}")
            continue
        artifact = matches[0]
        references.append({"artifact_id": artifact["id"], "artifact_digest": artifact["artifact_digest"],
                           "instrument_id": artifact["instrument_id"], "vial_position_id": artifact["vial_position_id"],
                           "component_id": artifact.get("component_id"), "calibration_type": artifact["calibration_type"],
                           "method": artifact["method"], "method_version": artifact["method_version"],
                           "capability": requirement["capability"], "required": requirement["required"]})
    payload["calibration_requirements"] = normalized
    payload["calibration_references"] = references
    payload["digest"] = canonical_digest(payload)
    return payload


def experiment_purpose(value: Any) -> str:
    return value if value in EXPERIMENT_PURPOSES else "research"
