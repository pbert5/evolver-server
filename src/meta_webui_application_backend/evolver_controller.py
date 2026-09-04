"""Durable central-side enrollment and synchronization for eVOLVER edges.

This deliberately uses a small JSON state file rather than the application
database: controller enrollment must survive a WebUI process restart even in a
minimal development deployment.  Production deployments may put the state
root on their persistent volume.  The file contains credential *digests*, never
the credentials returned to an edge at enrollment time.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Any, Mapping, Sequence

from .central_store import CentralControllerStore, configured_store
from .access_control import PERMISSIONS as _OPERATOR_PERMISSIONS
_OPERATOR_PERMISSIONS = frozenset(_OPERATOR_PERMISSIONS)
from .evolver_calibration import EVIDENCE_TYPES, FIRMWARE_SUPPORTED_PROCEDURES, calculate_candidate, digest, validate_observation, transition_session, CalibrationConflictError, derive_temperature
from .evolver_evidence import PUMP_COMPONENTS, blank_record, blank_statistics, pump_component
from .evolver_edge.bundle import BundleResolutionError, resolve_bundle
from .evolver_run_resources import add as add_run_resource, readiness as run_resource_readiness, transition as transition_run_resource
from .evolver_release_history import rollback_eligibility


STATE_ROOT_ENV = "META_WEBUI_EVOLVER_STATE_ROOT"
DEFAULT_TOKEN_TTL_SECONDS = 15 * 60
MAX_SYNC_BATCHES = 20
MAX_SYNC_RECORDS_PER_BATCH = 100
MAX_RUN_PROJECTION = 500
_LOCK = threading.RLock()
_COMMAND_CONDITION = threading.Condition(_LOCK)
_STATE_BACKENDS: dict[int, tuple[CentralControllerStore, int]] = {}
_EXPLICIT_STATE_PATHS: set[Path] = set()
_TERMINAL_COMMAND_DISPOSITIONS = frozenset({
    "completed",
    "stored",
    "failed",
    "rejected_stale_generation",
    "rejected_stale_revision",
    "rejected_unsafe",
    "rejected_invalid",
    "expired",
    "safe_stop_intent_recorded",
    "deferred_no_hardware_service",
    "rejected_lease",
    "quarantined",
})


def resolve_definition_bundle(
    definition: Mapping[str, Any],
    selected_calibration_artifacts: Sequence[Mapping[str, Any]],
    *,
    resolved_at: str,
) -> dict[str, Any]:
    """Resolve a central definition using caller-selected calibration evidence.

    This adapter performs no catalog lookup or recency selection.  Central
    policy selects the accepted artifacts and the pure resolver freezes their
    identities into the immutable bundle before its digest is calculated.
    """
    required = ("id", "name", "dataset_id", "dataset_revision")
    if any(not isinstance(definition.get(field), str) or not definition[field] for field in required):
        raise BundleResolutionError("ExperimentDefinition requires id, name, dataset_id, and dataset_revision")
    if not isinstance(resolved_at, str) or not resolved_at:
        raise BundleResolutionError("bundle resolution requires an explicit resolved_at timestamp")
    snapshot = definition.get("definition")
    if not isinstance(snapshot, Mapping) or not isinstance(snapshot.get("content"), Mapping):
        raise BundleResolutionError("ExperimentDefinition.definition must contain structured content")
    content = dict(snapshot["content"])
    # The schema compiler emits an immutable bundle-shaped content snapshot.
    # Accepting that shape here keeps central resolution independent of the
    # mutable catalog representation while preserving the legacy payload form.
    compiled = content.get("resolved_definition") is not None
    for field in ("schema_version", "execution_mode", "execution_plan"):
        if field not in content:
            raise BundleResolutionError(f"definition content requires {field} for bundle resolution")
    if not isinstance(content["execution_plan"], Mapping):
        raise BundleResolutionError("definition content execution_plan must be a mapping")
    plan = content["execution_plan"]
    if not isinstance(plan.get("initial_state"), str) or not isinstance(plan.get("states"), Mapping):
        raise BundleResolutionError("definition content execution_plan must be a compiled state-machine plan")
    if compiled and not isinstance(content.get("action_registry_revision"), str):
        raise BundleResolutionError("compiled definition requires action_registry_revision")
    requirements = definition.get("calibration_requirements", content.get("calibration_requirements", []))
    if not isinstance(requirements, list):
        raise BundleResolutionError("ExperimentDefinition.calibration_requirements must be a list")
    bundle = {
        "id": definition["id"], "name": definition["name"], "purpose": definition.get("purpose", "research"),
        "schema_version": content["schema_version"], "execution_mode": content["execution_mode"],
        "source": {"experiment_id": definition["id"], "dataset_revision": definition["dataset_revision"], "created_at": resolved_at},
        "resolved_definition": dict(snapshot), "execution_plan": dict(content["execution_plan"]),
        "runtime_parameters": content.get("runtime_parameters", []), "source_metadata": content.get("source_metadata", []),
        "calibration_requirements": requirements,
    }
    if compiled:
        bundle["action_registry_revision"] = content["action_registry_revision"]
    return resolve_bundle(bundle, selected_calibration_artifacts)


@dataclass(frozen=True)
class OperatorIdentity:
    """An identity asserted by the deployment authentication perimeter.

    The browser's ``actingUsername`` is deliberately not accepted here.  A
    reverse/OIDC proxy may set the configured trusted header after it has
    authenticated a request; this application only consumes that assertion.
    Deployments must ensure clients cannot reach this service while supplying
    that header themselves.
    """
    subject: str
    source: str
    permissions: frozenset[str]


def operator_from_headers(headers: Any) -> OperatorIdentity | None:
    """Compatibility seam for a trusted production perimeter identity."""
    return operator_from_request(headers, None, trusted_proxy=True)


def operator_from_request(headers: Any, cookie_header: str | None, *, trusted_proxy: bool = False) -> OperatorIdentity | None:
    from .access_control import identity_for_request, parse_cookie_header
    identity = identity_for_request(headers, parse_cookie_header(cookie_header), trusted_proxy=trusted_proxy)
    return OperatorIdentity(subject=identity.username, source=identity.source, permissions=identity.permissions) if identity else None


def _require_operator(operator: OperatorIdentity | None, permission: str) -> tuple[HTTPStatus, dict[str, Any]] | None:
    if operator is None:
        return HTTPStatus.UNAUTHORIZED, _error("an authenticated deployment operator is required", "OperatorAuthenticationRequired")
    if permission not in operator.permissions:
        return HTTPStatus.FORBIDDEN, _error(f"operator lacks {permission} permission", "OperatorPermissionDenied")
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _calibration_event(event_type: str, artifact_id: str, *, actor: str | None = None,
                       reason: str | None = None, details: Mapping[str, Any] | None = None,
                       **projection: Any) -> dict[str, Any]:
    """Serialize a calibration event using the LinkML contract.

    The short keys are retained as a read-model compatibility projection.  A
    few existing consumers also use the event context at the top level, so
    those values remain alongside the schema-shaped ``details`` payload.
    """
    occurred_at = _iso()
    event: dict[str, Any] = {
        "id": f"calibration-event-{uuid.uuid4()}",
        "event_type": event_type,
        "artifact_id": artifact_id,
        "occurred_at": occurred_at,
        "type": event_type,
        "at": occurred_at,
        **copy.deepcopy(projection),
    }
    if actor is not None:
        event["actor"] = actor
        event["by"] = actor
    if reason is not None:
        event["reason"] = reason
    if details is not None:
        event["details"] = {"value": copy.deepcopy(dict(details))}
    return event


def _parse_time(value: Any) -> datetime:
    """Parse projection timestamps conservatively for bounded telemetry."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return _now()


def _digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def state_path(state_root: Path | None = None) -> Path:
    root = state_root or Path(os.environ.get(STATE_ROOT_ENV, ".meta-webui-evolver-state"))
    path = root / "central-controller.json"
    if state_root is not None:
        _EXPLICIT_STATE_PATHS.add(path)
    return path


def _read(path: Path) -> dict[str, Any]:
    # Kept as an explicit compatibility/read-only seam for recovery tooling.
    # Runtime protocol operations use ``_state`` and its configured repository.
    if not path.exists(): return {}
    try: value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise RuntimeError(f"central eVOLVER state is unreadable: {exc}") from exc
    if not isinstance(value, dict): raise RuntimeError("central eVOLVER state must be an object")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    backend = _STATE_BACKENDS.pop(id(value), None)
    if backend is not None:
        backend[0].save(value, backend[1])
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _identity(state: dict[str, Any]) -> dict[str, str]:
    identity = state.get("webui_controller")
    if not isinstance(identity, dict):
        identity = {
            "id": f"webui-{uuid.uuid4()}",
            "public_key_fingerprint": secrets.token_urlsafe(32),
            "created_at": _iso(),
        }
        state["webui_controller"] = identity
    return identity  # type: ignore[return-value]


def _state(path: Path) -> dict[str, Any]:
    # A configured legacy root is the one-time migration source.  Only a
    # caller that explicitly supplies a root (tests/recovery tooling) keeps
    # using JSON after PostgreSQL is configured.
    store = configured_store(json_path=path, explicit_state_root=path in _EXPLICIT_STATE_PATHS)
    result, revision = store.load()
    _STATE_BACKENDS[id(result)] = (store, revision)
    _identity(result)
    result.setdefault("enrollment_tokens", {})
    result.setdefault("controllers", {})
    result.setdefault("commands", {})
    # Catalog recovery is intentionally isolated from operational projections:
    # adopting a controller and managing its live runs must not require a
    # source-data import.  Values are version maps keyed by stable object id.
    result.setdefault("content_snapshots", {})
    result.setdefault("recovery_imports", [])
    result.setdefault("interventions", {})
    result.setdefault("deployments", [])
    result.setdefault("run_resource_assignments", [])
    result.setdefault("run_resource_events", [])
    result.setdefault("manual_control_leases", {})
    result.setdefault("endpoint_assignments", {})
    result.setdefault("release_history", [])
    result.setdefault("release_deployments", [])
    result.setdefault("release_events", [])
    result.setdefault("rollback_requests", [])
    result.setdefault("controller_lifecycle_events", [])
    result.setdefault("audit_events", [])
    result.setdefault("calibration_sessions", {})
    result.setdefault("calibration_artifacts", {})
    result.setdefault("calibration_events", [])
    result.setdefault("od_blank_records", [])
    metadata = result.setdefault("display_metadata", {})
    if isinstance(metadata, dict):
        metadata.setdefault("controllers", {})
        metadata.setdefault("instruments", {})
    return result


def controller_release_selection(*, state_root: Path | None = None) -> dict[str, Any] | None:
    """Return the durable controller release selection, if one exists."""
    with _LOCK:
        selection = _state(state_path(state_root)).get("controller_release_selection")
        return copy.deepcopy(selection) if isinstance(selection, dict) else None


def _allocate_name(mapping: dict[str, Any], prefix: str) -> str:
    used = {str(value) for value in mapping.values() if isinstance(value, str)}
    index = 1
    while f"{prefix} {index}" in used:
        index += 1
    return f"{prefix} {index}"


def _display_name(state: dict[str, Any], kind: str, stable_id: str, fallback: str | None = None) -> str:
    metadata = state.setdefault("display_metadata", {}).setdefault(kind, {})
    if not isinstance(metadata, dict):
        metadata = {}
        state["display_metadata"][kind] = metadata
    value = metadata.get(stable_id)
    if not isinstance(value, str) or not value.strip():
        value = fallback or _allocate_name(metadata, "eVOLVER Controller" if kind == "controllers" else "eVOLVER")
        metadata[stable_id] = value
    return value


def _inventory_upsert(current: list[Any], incoming: list[Any]) -> None:
    """Replace mutable inventory observations by stable instrument identity."""
    by_id = {item.get("id"): item for item in current if isinstance(item, dict) and isinstance(item.get("id"), str)}
    order = [item.get("id") for item in current if isinstance(item, dict) and isinstance(item.get("id"), str)]
    for item in incoming:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            continue
        instrument_id = item["id"]
        by_id[instrument_id] = copy.deepcopy(item)
        if instrument_id not in order:
            order.append(instrument_id)
    current[:] = [by_id[instrument_id] for instrument_id in order if instrument_id in by_id]


_HARDWARE_PROBE_OUTCOMES = frozenset({"open", "permission", "busy", "timeout", "protocol", "malformed", "status", "identity"})
_HARDWARE_ACTIONS = {
    "open": "retry_probe", "timeout": "retry_probe",
    "permission": "inspect_transport_access", "busy": "inspect_transport_access",
    "protocol": "inspect_hardware_protocol", "malformed": "inspect_hardware_protocol",
    "status": "inspect_hardware_status", "identity": "inspect_hardware_identity",
}


def _bounded_hardware_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize edge hardware evidence while bounding diagnostic payloads."""
    result = copy.deepcopy(dict(observation))
    for key in ("diagnostic", "recommended_action", "observed_at", "connection_state", "probe_outcome"):
        if isinstance(result.get(key), str):
            result[key] = result[key][:256]
    transport = result.get("transport")
    if isinstance(transport, dict) and isinstance(transport.get("candidates"), list):
        transport["candidates"] = [str(item)[:128] for item in transport["candidates"][:8]]
    evidence = result.get("transport_evidence")
    if isinstance(evidence, dict):
        result["transport_evidence"] = {
            str(key)[:48]: value[:256] if isinstance(value, str) else value
            for key, value in list(evidence.items())[:8]
            if isinstance(value, (str, int, float, bool)) or value is None
        }
    outcome = result.get("probe_outcome")
    if outcome not in _HARDWARE_PROBE_OUTCOMES:
        result.pop("probe_outcome", None)
        outcome = None
    if not isinstance(result.get("diagnostic"), str):
        reason = result.get("transport_evidence", {}).get("reason") if isinstance(result.get("transport_evidence"), dict) else None
        if isinstance(reason, str):
            result["diagnostic"] = reason[:256]
    if outcome is not None and not isinstance(result.get("recommended_action"), str):
        result["recommended_action"] = _HARDWARE_ACTIONS.get(outcome, "inspect_hardware_observation")
    return result


def _valid_observation_time(observation: Mapping[str, Any]) -> datetime | None:
    """Return an observation time only when the edge supplied a valid one."""
    value = observation.get("observed_at")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _should_accept_hardware_observation(current: Any, incoming: Mapping[str, Any]) -> bool:
    """Fence delayed typed observations when both sides carry valid times.

    Legacy and malformed observations have no trustworthy ordering signal, so
    they retain the pre-existing compatibility behavior and are accepted.
    """
    if not isinstance(current, Mapping):
        return True
    current_at = _valid_observation_time(current)
    incoming_at = _valid_observation_time(incoming)
    return current_at is None or incoming_at is None or incoming_at >= current_at


def _hardware_observation_from_sync(body: Mapping[str, Any], current: Any) -> dict[str, Any] | None:
    """Prefer the typed field and accept the former detected_hardware shape."""
    incoming = body.get("hardware_observation")
    if isinstance(incoming, dict):
        observation = _bounded_hardware_observation(incoming)
        return observation if _should_accept_hardware_observation(current, observation) else None
    legacy = body.get("detected_hardware")
    if isinstance(legacy, list):
        legacy = legacy[0] if legacy else None
    if isinstance(legacy, dict) and not isinstance(current, dict):
        return _bounded_hardware_observation(legacy)
    return None


def _normalized_telemetry(controller_id: str, records: list[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
        observed = {**record, **payload}
        captured = record.get("captured_at") or record.get("timestamp") or record.get("at")
        instrument_id = observed.get("instrument_id") or observed.get("evolver_id")
        if not instrument_id and isinstance(record.get("stream_id"), str) and record["stream_id"].startswith("instrument:"):
            instrument_id = record["stream_id"].split(":", 2)[1]
        channel_count = max([int(key.rsplit("_", 1)[1]) + 1 for key in observed if key.startswith(("thermistor_adc_", "photodiode_adc_")) and key.rsplit("_", 1)[1].isdigit()] or [1])
        for channel in range(channel_count):
            vial_ids = observed.get("vial_position_ids")
            vial_id = (vial_ids[channel] if isinstance(vial_ids, list) and channel < len(vial_ids) and isinstance(vial_ids[channel], str) else None) or observed.get("vial_position_id") or observed.get("vial_id")
            if not vial_id and instrument_id:
                vial_id = f"{instrument_id}:vial:{channel}"
            for source_key, metric, label in ((f"photodiode_adc_{channel}", "photodiode_raw", "ADC"), (f"thermistor_adc_{channel}", "thermistor_raw", "ADC")):
                value = observed.get(source_key)
                if isinstance(value, (int, float)):
                    result.append({"instrument_id": instrument_id, "controller_id": controller_id, "vial_position_id": vial_id, "stream_id": record.get("stream_id"), "sequence": record.get("sequence"),
                                   "channel_index": channel, "captured_at": captured, "metric": metric, "value": value,
                                   "unit": label, "calibration_state": "uncalibrated", "source": "edge_raw"})
            for source_key, metric, unit in (("od", "od", "OD600"), ("temperature_c", "temperature_c", "°C")):
                value = observed.get(source_key)
                calibration = observed.get("calibration_state") or observed.get("calibration", {}).get(source_key) if isinstance(observed.get("calibration"), dict) else observed.get("calibration_state")
                if isinstance(value, (int, float)) and calibration in {"calibrated", "valid", "verified"}:
                    result.append({"instrument_id": instrument_id, "controller_id": controller_id, "vial_position_id": vial_id, "stream_id": record.get("stream_id"), "sequence": record.get("sequence"),
                                   "channel_index": channel, "captured_at": captured, "metric": metric, "value": value,
                                   "unit": unit, "calibration_state": "calibrated", "source": "edge_calibrated"})
    return result


def _response_identity(state: dict[str, Any]) -> dict[str, str]:
    return copy.deepcopy(_identity(state))


def create_enrollment_token(*, server_url: str, ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
                            purpose: str = "enrollment", state_root: Path | None = None,
                            release_binding: Mapping[str, str] | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Issue a single-use, purpose-bound enrollment credential.

    A normal enrollment credential is deliberately insufficient to replace an
    existing binding.  ``live_handoff`` and ``forced_adoption`` credentials
    are separate operator actions, making a recovery takeover visible in both
    the central audit projection and the edge's durable binding history.
    """
    if not isinstance(server_url, str) or not server_url.strip():
        return HTTPStatus.BAD_REQUEST, _error("server_url is required")
    if ttl_seconds <= 0:
        return HTTPStatus.BAD_REQUEST, _error("ttl_seconds must be positive")
    if purpose not in {"enrollment", "repair", "live_handoff", "forced_adoption"}:
        return HTTPStatus.BAD_REQUEST, _error("invalid enrollment token purpose")
    if release_binding is not None:
        required = ("release", "source_revision", "manifest_sha256")
        if (not isinstance(release_binding, Mapping)
                or any(not isinstance(release_binding.get(key), str) or not release_binding[key] for key in required)
                or any(key not in required for key in release_binding)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release_binding["release"])
                or not re.fullmatch(r"[0-9a-f]{7,64}", release_binding["source_revision"])
                or not re.fullmatch(r"[0-9a-f]{64}", release_binding["manifest_sha256"])):
            return HTTPStatus.BAD_REQUEST, _error("invalid immutable release binding")
    with _LOCK:
        path = state_path(state_root)
        state = _state(path)
        token = secrets.token_urlsafe(32)
        expires_at = _now() + timedelta(seconds=ttl_seconds)
        token_id = f"enroll-{uuid.uuid4()}"
        state["enrollment_tokens"][_digest(token)] = {
            "id": token_id, "server_url": server_url.rstrip("/"), "purpose": purpose,
            "expires_at": _iso(expires_at), "used_at": None,
            **({"release_binding": dict(release_binding)} if release_binding is not None else {}),
        }
        _write(path, state)
    return HTTPStatus.CREATED, {
        "enrollment_token": token,
        "token_id": token_id,
        "expires_at": _iso(expires_at),
        "server_url": server_url.rstrip("/"),
        "purpose": purpose,
        "webui_controller": _response_identity(state),
    }


def enrollment_token_release_binding(token_id: str, *, state_root: Path | None = None) -> dict[str, str] | None:
    if not isinstance(token_id, str) or not re.fullmatch(r"enroll-[0-9a-f-]{36}", token_id):
        return None
    with _LOCK:
        state = _state(state_path(state_root))
        for record in state.get("enrollment_tokens", {}).values():
            if isinstance(record, dict) and record.get("id") == token_id:
                binding = record.get("release_binding")
                if isinstance(binding, dict) and set(binding) == {"release", "source_revision", "manifest_sha256"}:
                    return {key: binding[key] for key in binding}
                return None
    return None


def enroll(body: Any, *, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    if not isinstance(body, dict):
        return HTTPStatus.BAD_REQUEST, _error("body must be an object")
    controller_id = body.get("controller_id")
    token = body.get("enrollment_token")
    if not isinstance(controller_id, str) or not controller_id.strip() or not isinstance(token, str) or not token:
        return HTTPStatus.BAD_REQUEST, _error("controller_id and enrollment_token are required")
    with _LOCK:
        path = state_path(state_root)
        state = _state(path)
        token_record = state["enrollment_tokens"].get(_digest(token))
        if not isinstance(token_record, dict):
            return HTTPStatus.UNAUTHORIZED, _error("invalid enrollment token", "EnrollmentRejected")
        try:
            expired = datetime.fromisoformat(str(token_record["expires_at"]).replace("Z", "+00:00")) <= _now()
        except (KeyError, ValueError):
            expired = True
        if token_record.get("used_at") or expired:
            return HTTPStatus.UNAUTHORIZED, _error("enrollment token is used or expired", "EnrollmentRejected")
        controllers: dict[str, Any] = state["controllers"]
        existing = controllers.get(controller_id)
        requested_mode = body.get("binding_mode", "enrollment")
        if requested_mode not in {"enrollment", "repair", "live_handoff", "forced_adoption"}:
            return HTTPStatus.BAD_REQUEST, _error("invalid binding_mode")
        token_purpose = token_record.get("purpose", "enrollment")
        supplied_binding = body.get("current_binding") if isinstance(body.get("current_binding"), dict) else None
        supplied_identity = supplied_binding.get("webui_controller_id") if supplied_binding else None
        supplied_generation = supplied_binding.get("generation") if supplied_binding else None
        central_id = _identity(state)["id"]

        # Same WebUI repair is intentionally not a handoff and retains the
        # fencing epoch.  It only rotates the machine credential.
        if isinstance(existing, dict):
            binding = existing["binding"]
            if requested_mode != "repair" or token_purpose not in {"enrollment", "repair"}:
                return HTTPStatus.CONFLICT, _error("controller is already enrolled; explicitly request credential repair", "EnrollmentConflict", state)
            if binding["webui_controller_id"] != central_id:
                return HTTPStatus.CONFLICT, _error("stored controller binding belongs to a different WebUI", "EnrollmentConflict", state)
            credential = secrets.token_urlsafe(48)
            existing["credential_digest"] = _digest(credential)
            binding["status"] = "bound"
            binding["bound_at"] = _iso()
            token_record["used_at"] = _iso()
            _write(path, state)
            return HTTPStatus.OK, {"controller_id": controller_id, "credential": credential,
                                   "binding": copy.deepcopy(binding), "webui_controller": _response_identity(state),
                                   "binding_path": "repair"}

        # A newly-created central can only replace a durable edge binding by
        # an explicit, purpose-bound takeover.  An ordinary token never
        # silently steals an active edge.
        if supplied_identity and supplied_identity != central_id:
            if requested_mode not in {"live_handoff", "forced_adoption"} or token_purpose != requested_mode:
                return HTTPStatus.CONFLICT, _error("controller is already bound elsewhere; choose live handoff or forced adoption explicitly", "EnrollmentConflict", state)
            if requested_mode == "forced_adoption" and body.get("operator_confirmed") is not True:
                return HTTPStatus.FORBIDDEN, _error("forced adoption requires operator_confirmed=true", "AdoptionConfirmationRequired", state)
            if requested_mode == "live_handoff" and body.get("handoff_released") is not True:
                return HTTPStatus.FORBIDDEN, _error("live handoff requires release by the currently bound WebUI", "HandoffReleaseRequired", state)
            if not isinstance(supplied_generation, int) or supplied_generation < 1:
                return HTTPStatus.BAD_REQUEST, _error("current_binding generation is required for takeover")
            generation = supplied_generation + 1
            binding_path = requested_mode
        elif supplied_identity == central_id:
            # State loss with a recovered copy of the same central identity is
            # a repair, not an epoch change.
            if requested_mode != "repair" or token_purpose not in {"enrollment", "repair"}:
                return HTTPStatus.CONFLICT, _error("existing binding requires explicit repair", "EnrollmentConflict", state)
            generation = int(supplied_generation) if isinstance(supplied_generation, int) else 1
            binding_path = "repair"
        else:
            if requested_mode != "enrollment" or token_purpose != "enrollment":
                return HTTPStatus.CONFLICT, _error("unbound controller requires an enrollment token", "EnrollmentConflict", state)
            generation, binding_path = 1, "enrollment"
        credential = secrets.token_urlsafe(48)
        controllers[controller_id] = {
            "id": controller_id,
            "public_key_fingerprint": body.get("public_key_fingerprint"),
            "credential_digest": _digest(credential),
            "binding": {"webui_controller_id": _identity(state)["id"], "server_url": token_record["server_url"], "controller_generation": generation, "bound_at": _iso(), "status": "bound"},
            "connection_state": "disconnected", "last_sync_at": None, "last_heartbeat": None,
            "lifecycle_state": "active",
            "inventory": [], "events": [], "acknowledgements": [], "telemetry": [], "recovery_manifest": None,
            "event_cursors": {}, "telemetry_cursors": {},
            "binding_history": [{"path": binding_path, "at": _iso(), "previous_webui_controller_id": supplied_identity,
                                 "previous_generation": supplied_generation}],
        }
        controllers[controller_id]["name"] = _display_name(state, "controllers", controller_id)
        token_record["used_at"] = _iso()
        _write(path, state)
    return HTTPStatus.CREATED, {
        "controller_id": controller_id,
        "credential": credential,
        "binding": copy.deepcopy(controllers[controller_id]["binding"]),
        "webui_controller": _response_identity(state),
        "binding_path": binding_path,
    }


def sync(body: Any, *, credential: str | None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    if not isinstance(body, dict):
        return HTTPStatus.BAD_REQUEST, _error("body must be an object")
    controller_id, generation = body.get("controller_id"), body.get("controller_generation")
    if not isinstance(controller_id, str) or not isinstance(generation, int):
        return HTTPStatus.BAD_REQUEST, _error("controller_id and integer controller_generation are required")
    with _LOCK:
        path = state_path(state_root)
        state = _state(path)
        controller = state["controllers"].get(controller_id)
        if not isinstance(controller, dict) or not credential or not secrets.compare_digest(str(controller.get("credential_digest", "")), _digest(credential)):
            return HTTPStatus.UNAUTHORIZED, _error("controller credential is invalid", "AuthenticationFailed", state)
        binding = controller["binding"]
        # Upgrade bootstrap JSON state in place.  These are operational
        # projections, so older deployments can resume without data loss.
        controller.setdefault("events", [])
        controller.setdefault("telemetry", [])
        controller.setdefault("event_cursors", {})
        controller.setdefault("telemetry_cursors", {})
        controller.setdefault("acknowledgements", [])
        expected_generation = binding["controller_generation"]
        if generation != expected_generation:
            return HTTPStatus.CONFLICT, _error("controller generation is stale or unknown", "GenerationConflict", state, expected_generation=expected_generation)
        # The incoming batch is an auditable central projection. Edge remains
        # authoritative; identical retries are folded by stable ids/sequences.
        controller["connection_state"] = "connected"
        controller["last_sync_at"] = _iso()
        if "heartbeat" in body:
            controller["last_heartbeat"] = body["heartbeat"]
        observation = _hardware_observation_from_sync(body, controller.get("hardware_observation"))
        if observation is not None:
            # Physical evidence is edge-owned and remains distinct from the
            # durable instrument inventory. Typed observations win over the
            # legacy detected_hardware compatibility field.
            controller["hardware_observation"] = observation
        for key in ("inventory", "command_acknowledgements"):
            incoming = body.get(key)
            if isinstance(incoming, list):
                existing = controller[{"inventory": "inventory", "command_acknowledgements": "acknowledgements"}[key]]
                if key == "inventory":
                    _inventory_upsert(existing, incoming)
                    metadata = state.setdefault("display_metadata", {}).setdefault("instruments", {})
                    for item in incoming:
                        if isinstance(item, dict) and isinstance(item.get("id"), str):
                            _display_name(state, "instruments", item["id"], item.get("name"))
                else:
                    _append_unique(existing, incoming, key)
        try:
            blank_records = body.get("od_blank_records")
            if isinstance(blank_records, list):
                _ingest_od_blank_records(state, controller_id, generation, blank_records)
            _ingest_event_batches(controller, body.get("event_batches"))
            _ingest_telemetry_batches(controller, body.get("telemetry_batches"))
        except ValueError as exc:
            return HTTPStatus.BAD_REQUEST, _error(str(exc), "InvalidSyncBatch", state)
        acknowledgements = body.get("command_acknowledgements")
        if isinstance(acknowledgements, list):
            _reconcile_command_acknowledgements(state["commands"].get(controller_id, []), acknowledgements, generation)
            for acknowledgement in acknowledgements:
                if not isinstance(acknowledgement, dict): continue
                command = next((item for item in state["commands"].get(controller_id, []) if isinstance(item, dict) and item.get("command_id") == acknowledgement.get("command_id")), None)
                if not isinstance(command, dict) or command.get("command_kind") != "store_calibration_artifact": continue
                artifact = state.get("calibration_artifacts", {}).get(command.get("artifact_id")); matches = acknowledgement.get("artifact_id") == command.get("artifact_id") and acknowledgement.get("artifact_digest") == command.get("artifact_digest")
                if acknowledgement.get("disposition") == "stored" and not matches:
                    command["disposition"] = "rejected_invalid"; command["acknowledgement"] = copy.deepcopy(acknowledgement); continue
                if isinstance(artifact, dict):
                    status = "stored" if acknowledgement.get("disposition") == "stored" and matches else ("failed" if acknowledgement.get("disposition") in {"failed", "rejected_invalid", "rejected_unsafe"} else "pending")
                    if status == "pending":
                        continue
                    event_type = "distribution_stored" if status == "stored" else "distribution_failed"
                    prior = [event for event in _calibration_events(state, str(command.get("artifact_id")))
                             if _event_type(event) == event_type and _event_details(event).get("command_id") == command.get("command_id")]
                    if not prior:
                        state.setdefault("calibration_events", []).append(_calibration_event(
                            event_type, str(command.get("artifact_id")),
                            reason=None if status == "stored" else ("digest_or_generation_mismatch" if not matches else str(acknowledgement.get("disposition"))),
                            details={"controller_id": controller_id, "command_id": command.get("command_id"),
                                     "controller_generation": generation, "artifact_digest": command.get("artifact_digest"),
                                     "acknowledgement": copy.deepcopy(acknowledgement)},
                        ))
            # A requested full recovery manifest arrives in a durable command
            # acknowledgement on the *next* sync.  It is evidence from the
            # edge, not an instruction to overwrite central catalog content.
            for acknowledgement in acknowledgements:
                if isinstance(acknowledgement, dict) and isinstance(acknowledgement.get("recovery_manifest"), dict):
                    controller["recovery_manifest"] = copy.deepcopy(acknowledgement["recovery_manifest"])
        if isinstance(body.get("recovery_manifest"), dict):
            controller["recovery_manifest"] = copy.deepcopy(body["recovery_manifest"])
        if isinstance(body.get("recovery_summary"), dict):
            controller["recovery_summary"] = copy.deepcopy(body["recovery_summary"])
        _expire_commands(state["commands"].get(controller_id, []))
        _fence_lease_commands(state["commands"].get(controller_id, []), state.setdefault("manual_control_leases", {}).get(controller_id))
        commands = [copy.deepcopy(command) for command in state["commands"].get(controller_id, [])
                    if command.get("controller_generation") == generation
                    and command.get("delivery_eligible", True) is True
                    and command.get("disposition") not in _TERMINAL_COMMAND_DISPOSITIONS]
        command_projection = [copy.deepcopy(command) for command in state["commands"].get(controller_id, [])
                              if isinstance(command, dict) and command.get("controller_generation") == generation]
        _write(path, state)
        return HTTPStatus.OK, {
            "webui_controller": _response_identity(state), "controller_id": controller_id,
            "accepted_generation": generation, "controller_state": "connected", "commands": commands,
            "command_projection": command_projection,
            "desired_release": controller.get("desired_release"),
            "event_cursors": copy.deepcopy(controller["event_cursors"]),
            "telemetry_cursors": copy.deepcopy(controller["telemetry_cursors"]), "reconciliation_required": False,
        }


def queue_command(controller_id: str, command: dict[str, Any], *, state_root: Path | None = None) -> None:
    """Central mutation seam; every command is fenced before delivery."""
    with _LOCK:
        path = state_path(state_root)
        state = _state(path)
        controller = state["controllers"].get(controller_id)
        if not isinstance(controller, dict):
            raise KeyError(controller_id)
        if command.get("controller_generation") != controller["binding"]["controller_generation"]:
            raise ValueError("command generation does not match current binding")
        run_id = command.get("run_id")
        if run_id is not None:
            summary = controller.get("recovery_summary") or controller.get("recovery_manifest") or {}
            known_runs = summary.get("runs", []) if isinstance(summary, dict) else []
            if not isinstance(run_id, str) or not any(isinstance(run, dict) and run.get("id") == run_id for run in known_runs):
                raise ValueError("command run target does not belong to controller")
        state["commands"].setdefault(controller_id, []).append(copy.deepcopy(command))
        _write(path, state)
        _COMMAND_CONDITION.notify_all()


def wait_for_command(controller_id: str, body: Any, *, credential: str | None,
                     state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Authenticated, bounded outbound command delivery for an edge controller.

    The edge supplies the last durable delivery cursor.  A cursor advances only
    after the edge has durably processed the command, so a lost HTTP response
    causes safe at-least-once redelivery and the edge command id remains the
    idempotency authority.
    """
    if not isinstance(body, dict):
        body = {}
    generation = body.get("controller_generation")
    if isinstance(generation, bool) or not isinstance(generation, int):
        return HTTPStatus.BAD_REQUEST, _error("controller_generation must be an integer")
    cursor = body.get("last_cursor", 0)
    if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
        return HTTPStatus.BAD_REQUEST, _error("last_cursor must be a non-negative integer")
    timeout = body.get("wait_seconds", 25)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 <= timeout <= 30:
        return HTTPStatus.BAD_REQUEST, _error("wait_seconds must be between 0 and 30")
    deadline = _now().timestamp() + float(timeout)
    path = state_path(state_root)
    with _COMMAND_CONDITION:
        while True:
            state = _state(path)
            controller = state.get("controllers", {}).get(controller_id)
            if not isinstance(controller, dict) or not credential or not secrets.compare_digest(
                    str(controller.get("credential_digest", "")), _digest(credential)):
                return HTTPStatus.UNAUTHORIZED, _error("controller credential is invalid", "AuthenticationFailed", state)
            expected = controller.get("binding", {}).get("controller_generation")
            if generation != expected:
                return HTTPStatus.CONFLICT, _error("controller generation is stale or unknown", "GenerationConflict", state,
                                                   expected_generation=expected)
            commands = state.setdefault("commands", {}).setdefault(controller_id, [])
            _expire_commands(commands)
            _fence_lease_commands(commands, state.setdefault("manual_control_leases", {}).get(controller_id))
            eligible = [item for item in commands if isinstance(item, dict)
                        and item.get("controller_generation") == generation
                        and item.get("delivery_eligible", True) is True
                        and item.get("disposition") not in _TERMINAL_COMMAND_DISPOSITIONS
                        and (int(item.get("delivery_cursor", 0)) > cursor
                             or (item.get("disposition") == "queued" and int(item.get("delivery_cursor", 0)) <= cursor))]
            if eligible:
                # Emergency stop is safety-priority and cannot queue behind
                # stale ordinary actuator work.
                command = sorted(eligible, key=lambda item: (0 if item.get("command_kind") == "emergency_safe_stop" else 1,
                                                              int(item.get("delivery_cursor", 0))))[0]
                command["disposition"] = "delivered"
                command["delivered_at"] = _iso()
                _write(path, state)
                return HTTPStatus.OK, {"controller_id": controller_id, "controller_generation": generation,
                                       "command": copy.deepcopy(command), "cursor": command["delivery_cursor"],
                                       "timed_out": False}
            remaining = deadline - _now().timestamp()
            if remaining <= 0:
                return HTTPStatus.OK, {"controller_id": controller_id, "controller_generation": generation,
                                       "command": None, "cursor": cursor, "timed_out": True}
            _COMMAND_CONDITION.wait(timeout=remaining)


def release_handoff(body: Any, *, credential: str | None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Release a reachable binding before a live handoff.

    This deliberately requires the current machine credential.  A new WebUI
    cannot manufacture a release; if the old central is down the operator must
    use the separately-confirmed forced-adoption route instead.
    """
    if not isinstance(body, dict) or not isinstance(body.get("controller_id"), str):
        return HTTPStatus.BAD_REQUEST, _error("controller_id is required")
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        controller = state["controllers"].get(body["controller_id"])
        if not isinstance(controller, dict) or not credential or not secrets.compare_digest(str(controller.get("credential_digest", "")), _digest(credential)):
            return HTTPStatus.UNAUTHORIZED, _error("controller credential is invalid", "AuthenticationFailed", state)
        binding = controller["binding"]
        binding["status"] = "handoff_released"
        controller.setdefault("binding_history", []).append({"path": "live_handoff_release", "at": _iso(),
                                                                "target_server_url": body.get("target_server_url")})
        _write(path, state)
        return HTTPStatus.OK, {"controller_id": controller["id"], "released_generation": binding["controller_generation"],
                               "webui_controller": _response_identity(state)}


def _append_unique(existing: list[Any], incoming: list[Any], kind: str) -> None:
    def identity(value: Any) -> str:
        if isinstance(value, dict):
            for name in ("event_id", "command_id", "id", "sequence", "stream_id"):
                if name in value:
                    return f"{name}:{value[name]}"
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    known = {identity(value) for value in existing}
    for value in incoming:
        marker = identity(value)
        if marker not in known:
            existing.append(copy.deepcopy(value))
            known.add(marker)


def _contiguous_cursor(records: list[Any], stream_key: str, stream_id: str) -> int:
    sequences = {record.get("sequence") for record in records if isinstance(record, dict) and record.get(stream_key) == stream_id and isinstance(record.get("sequence"), int) and record["sequence"] > 0}
    cursor = 0
    while cursor + 1 in sequences:
        cursor += 1
    return cursor


def _ingest_event_batches(controller: dict[str, Any], batches: Any) -> None:
    if batches is None:
        return
    if not isinstance(batches, list):
        raise ValueError("event_batches must be a list")
    if len(batches) > MAX_SYNC_BATCHES:
        raise ValueError("too many event batches")
    events = controller["events"]
    by_key = {(event.get("run_id"), event.get("sequence")): event for event in events if isinstance(event, dict)}
    for batch in batches:
        if not isinstance(batch, dict) or not isinstance(batch.get("run_id"), str) or not isinstance(batch.get("records"), list):
            raise ValueError("event batch requires run_id and records")
        if len(batch["records"]) > MAX_SYNC_RECORDS_PER_BATCH:
            raise ValueError("event batch is too large")
        for event in batch["records"]:
            if not isinstance(event, dict) or event.get("run_id") != batch["run_id"] or not isinstance(event.get("sequence"), int) or event["sequence"] <= 0:
                raise ValueError("event record has invalid run_id or sequence")
            key = (event["run_id"], event["sequence"])
            prior = by_key.get(key)
            if prior is not None and _canonical_json(prior) != _canonical_json(event):
                raise ValueError("event sequence conflicts with durable central record")
            if prior is None:
                copied = copy.deepcopy(event); events.append(copied); by_key[key] = copied
        controller["event_cursors"][batch["run_id"]] = _contiguous_cursor(events, "run_id", batch["run_id"])


def _ingest_telemetry_batches(controller: dict[str, Any], batches: Any) -> None:
    if batches is None:
        return
    if not isinstance(batches, list):
        raise ValueError("telemetry_batches must be a list")
    if len(batches) > MAX_SYNC_BATCHES:
        raise ValueError("too many telemetry batches")
    telemetry = controller["telemetry"]
    by_key = {(record.get("stream_id"), record.get("sequence")): record for record in telemetry if isinstance(record, dict)}
    for batch in batches:
        if not isinstance(batch, dict) or not isinstance(batch.get("stream_id"), str) or not isinstance(batch.get("records"), list):
            raise ValueError("telemetry batch requires stream_id and records")
        records = batch["records"]
        if len(records) > MAX_SYNC_RECORDS_PER_BATCH:
            raise ValueError("telemetry batch is too large")
        if records:
            sequences = [record.get("sequence") for record in records if isinstance(record, dict)]
            if sequences != list(range(batch.get("first_sequence", -1), batch.get("last_sequence", -1) + 1)):
                raise ValueError("telemetry batch sequence range is invalid")
        for record in records:
            if not isinstance(record, dict) or record.get("stream_id") != batch["stream_id"] or not isinstance(record.get("sequence"), int) or record["sequence"] <= 0:
                raise ValueError("telemetry record has invalid stream_id or sequence")
            key = (record["stream_id"], record["sequence"])
            prior = by_key.get(key)
            if prior is not None and _canonical_json(prior) != _canonical_json(record):
                raise ValueError("telemetry sequence conflicts with durable central record")
            if prior is None:
                copied = copy.deepcopy(record); telemetry.append(copied); by_key[key] = copied
        controller["telemetry_cursors"][batch["stream_id"]] = _contiguous_cursor(telemetry, "stream_id", batch["stream_id"])


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _ingest_od_blank_records(state: dict[str, Any], controller_id: str, generation: int, records: list[Any]) -> None:
    """Persist edge blank evidence idempotently; never create an artifact."""
    if len(records) > MAX_SYNC_RECORDS_PER_BATCH:
        raise ValueError("too many OD blank records")
    stored = state.setdefault("od_blank_records", [])
    if not isinstance(stored, list):
        raise ValueError("OD blank evidence store is invalid")
    by_key = {(item.get("controller_id"), item.get("record_id")): item
              for item in stored if isinstance(item, dict)}
    for incoming in records:
        normalized = blank_record(incoming, controller_id=controller_id, controller_generation=generation)
        key = (controller_id, normalized["record_id"])
        prior = by_key.get(key)
        if prior is not None:
            if _canonical_json(prior) != _canonical_json(normalized):
                raise ValueError("OD blank record conflicts with durable central evidence")
            continue
        stored.append(copy.deepcopy(normalized))
        by_key[key] = stored[-1]


def od_blank_evidence(*, instrument_id: str | None = None, channel_index: int | None = None,
                      state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Read-only projection of repeated raw OD blank evidence and statistics."""
    with _LOCK:
        state = _state(state_path(state_root))
        records = [copy.deepcopy(item) for item in state.get("od_blank_records", []) if isinstance(item, dict)]
        if instrument_id is not None:
            records = [item for item in records if item.get("instrument_id") == instrument_id]
        if channel_index is not None:
            records = [item for item in records if item.get("channel_index") == channel_index]
        records.sort(key=lambda item: (str(item.get("captured_at", "")), str(item.get("record_id", ""))))
        return HTTPStatus.OK, {"od_blank_records": records, "statistics": blank_statistics(records),
                               "read_only": True, "acceptance": "OD blank evidence cannot establish or accept OD600 calibration",
                               "webui_controller": _response_identity(state)}


def _expire_commands(commands: list[Any]) -> None:
    """Move expired intent to a durable terminal projection before delivery."""
    now = _now()
    for command in commands:
        if not isinstance(command, dict) or command.get("disposition") in _TERMINAL_COMMAND_DISPOSITIONS:
            continue
        expires_at = command.get("expires_at")
        if expires_at is None or _parse_time(expires_at) > now:
            continue
        command["disposition"] = "expired"
        command["delivery_eligible"] = False
        command["expired_at"] = _iso(now)
        command["expiration_reason"] = "ttl_expired"


def _fence_lease_commands(commands: list[Any], lease: Mapping[str, Any] | None) -> None:
    """Retire queued manual commands whose lease was revoked or expired."""
    for command in commands:
        if not isinstance(command, dict) or command.get("disposition") in _TERMINAL_COMMAND_DISPOSITIONS:
            continue
        if not isinstance(lease, Mapping) or command.get("lease_id") != lease.get("lease_id"):
            continue
        if lease.get("revoked_at") or _lease_status(lease) == "expired":
            command.update({"disposition": "rejected_lease", "delivery_eligible": False,
                            "lease_fenced_at": _iso(),
                            "lease_fence_reason": "revoked" if lease.get("revoked_at") else "expired"})


def _reconcile_command_acknowledgements(commands: list[Any], acknowledgements: list[Any], generation: int) -> None:
    """Persist terminal edge outcomes and retire only their matching delivery.

    An acknowledgement is authenticated by the controller credential at the
    enclosing sync boundary.  It still cannot acknowledge a command from a
    different controller generation, nor turn a non-terminal observation into
    an implicit completion.  Keeping the command record (rather than deleting
    it) leaves a durable audit trail while preventing needless redelivery.
    """
    terminal_by_id = {
        acknowledgement["command_id"]: acknowledgement
        for acknowledgement in acknowledgements
        if isinstance(acknowledgement, dict)
        and isinstance(acknowledgement.get("command_id"), str)
        and acknowledgement.get("disposition") in _TERMINAL_COMMAND_DISPOSITIONS
    }
    for command in commands:
        if not isinstance(command, dict) or command.get("controller_generation") != generation:
            continue
        acknowledgement = terminal_by_id.get(command.get("command_id"))
        if acknowledgement is not None and command.get("disposition") not in _TERMINAL_COMMAND_DISPOSITIONS:
            command["disposition"] = acknowledgement["disposition"]
            command["acknowledgement"] = copy.deepcopy(acknowledgement)
            command["acknowledged_at"] = _iso()
            command["delivery_eligible"] = False


def _error(message: str, kind: str = "BadRequest", state: dict[str, Any] | None = None, **details: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"error": message, "kind": kind, **details}
    if state is not None:
        result["webui_controller"] = _response_identity(state)
    return result


MACHINE_FACING_PATHS = frozenset({
    "/api/evolver/controllers/enroll",
    "/api/evolver/controllers/handoff/release",
    "/api/evolver/controllers/sync",
    "/api/evolver/controllers/commands/wait",
})
"""Controller-bearer authenticated paths which ingress sends to control.

``sync`` is intentionally the bounded exchange for heartbeats, telemetry,
events, recovery manifests, command delivery, and command acknowledgements.
Keep this set exact: all other eVOLVER paths require the WebUI operator
gateway.
"""


def route_owner(path: str) -> str | None:
    """Classify every accepted eVOLVER route for public ingress ownership."""
    if path in MACHINE_FACING_PATHS:
        return "machine"
    if path in {"/api/evolver/enrollment-tokens", "/api/evolver/server-endpoints", "/api/evolver/controllers", "/api/evolver/controllers/freshness", "/api/evolver/runs", "/api/evolver/instruments", "/api/evolver/maintenance", "/api/evolver/dashboard", "/api/evolver/calibrations", "/api/evolver/calibration-workspace", "/api/evolver/od-blanks", "/api/evolver/releases/history", "/api/evolver/audit-events", "/api/evolver/experiments/validate", "/api/evolver/experiments/describe", "/api/evolver/experiments/plan"} or path.startswith(("/api/evolver/controllers/", "/api/evolver/runs/", "/api/evolver/instruments/", "/api/evolver/interventions/", "/api/evolver/calibrations/", "/api/evolver/releases/")):
        return "human"
    return None


def handles(path: str) -> bool:
    return route_owner(path) is not None


def controllers(*, controller_id: str | None = None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Read-only central projection for the controller observability UI.

    Credentials and their hashes deliberately never cross this boundary.
    """
    with _LOCK:
        state = _state(state_path(state_root))
        records = state["controllers"]
        changed = False
        for stable_id, record in records.items():
            if isinstance(record, dict) and not isinstance(record.get("name"), str):
                record["name"] = _display_name(state, "controllers", str(stable_id))
                changed = True
        if changed:
            _write(state_path(state_root), state)
        if controller_id is not None:
            record = records.get(controller_id)
            if not isinstance(record, dict):
                return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
            projection = _public_controller(record)
            projection["endpoint_assignment"] = copy.deepcopy(state.get("endpoint_assignments", {}).get(controller_id))
            return HTTPStatus.OK, {"webui_controller": _response_identity(state), "controller": projection}
        projections = []
        for stable_id, record in sorted(records.items()):
            if isinstance(record, dict):
                projection = _public_controller(record)
                projection["endpoint_assignment"] = copy.deepcopy(state.get("endpoint_assignments", {}).get(stable_id))
                projections.append(projection)
        response = {"webui_controller": _response_identity(state), "controllers": projections}
        response["controller_endpoints"] = server_endpoints()[1].get("controller_endpoints", [])
        return HTTPStatus.OK, response


def rename_entity(kind: str, stable_id: str, name: Any, *, operator: OperatorIdentity | None,
                  state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_controller")
    if denied:
        return denied
    if kind not in {"controllers", "instruments"} or not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        return HTTPStatus.BAD_REQUEST, _error("name must be a non-empty string of at most 120 characters")
    with _LOCK:
        path = state_path(state_root); state = _state(path)
        if kind == "controllers":
            if stable_id not in state["controllers"]:
                return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        else:
            if not any(isinstance(item, dict) and item.get("id") == stable_id for controller in state["controllers"].values() if isinstance(controller, dict) for item in controller.get("inventory", [])):
                return HTTPStatus.NOT_FOUND, _error("instrument not found", "NotFound", state)
        state.setdefault("display_metadata", {}).setdefault(kind, {})[stable_id] = name.strip()
        state.setdefault("audit_events", []).append({"type": f"{kind[:-1]}_renamed", "id": stable_id, "name": name.strip(), "occurred_at": _iso(), "by": operator.subject})
        if kind == "controllers":
            state["controllers"][stable_id]["name"] = name.strip()
        _write(path, state)
        return HTTPStatus.OK, {"id": stable_id, "name": name.strip(), "webui_controller": _response_identity(state)}


def server_endpoints() -> tuple[HTTPStatus, dict[str, Any]]:
    """Return the immutable deployment registry used for central assignment.

    URL add/edit/archive is deployment configuration, not an operator API.
    Operators may assign a controller to one of these validated entries.
    """
    from .evolver_config import controller_endpoints
    try:
        return HTTPStatus.OK, {"controller_endpoints": controller_endpoints(),
                               "registry_mode": "deployment_configured",
                               "registry_mutable": False,
                               "assignment_mutable": True}
    except ValueError as exc:
        return HTTPStatus.SERVICE_UNAVAILABLE, _error(str(exc), "EndpointConfigurationInvalid")


def assign_controller_endpoint(controller_id: str, body: Any, *, operator: OperatorIdentity | None,
                                state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_controller")
    if denied: return denied
    if not isinstance(body, dict) or not isinstance(body.get("endpoint_id"), str):
        return HTTPStatus.BAD_REQUEST, _error("endpoint_id is required")
    from .evolver_config import controller_endpoints
    try: endpoints = controller_endpoints()
    except ValueError as exc: return HTTPStatus.SERVICE_UNAVAILABLE, _error(str(exc), "EndpointConfigurationInvalid")
    endpoint = next((item for item in endpoints if item["id"] == body["endpoint_id"]), None)
    if endpoint is None or endpoint.get("controller_reachable") is not True or endpoint.get("enabled") is not True:
        return HTTPStatus.CONFLICT, _error("endpoint is not an approved controller-reachable endpoint", "EndpointNotApproved")
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        if controller_id not in state["controllers"]: return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        assignment = {"controller_id": controller_id, "endpoint_id": endpoint["id"], "url": endpoint["url"], "assigned_at": _iso(), "assigned_by": operator.subject}
        state["endpoint_assignments"][controller_id] = assignment
        _audit(state, "controller_endpoint_assigned", actor=operator.subject, details=assignment)
        _write(path, state)
        return HTTPStatus.OK, {"assignment": copy.deepcopy(assignment), "webui_controller": _response_identity(state)}


def _public_controller(record: dict[str, Any]) -> dict[str, Any]:
    result = {key: copy.deepcopy(value) for key, value in record.items() if key not in {"credential_digest", "events", "acknowledgements", "telemetry_ranges", "telemetry"}}
    result["sync_freshness"] = _sync_freshness(record)
    observation = result.get("hardware_observation")
    if isinstance(observation, dict):
        # The latest edge observation is a singleton, including disconnects;
        # connection_state remains a separate controller-level field.
        result["detected_hardware"] = [_bounded_hardware_observation(observation)]
    return result


def _calibration_events(state: Mapping[str, Any], artifact_id: str) -> list[dict[str, Any]]:
    return [event for event in state.get("calibration_events", [])
            if isinstance(event, dict) and event.get("artifact_id") == artifact_id]


def _event_type(event: Mapping[str, Any]) -> str:
    return str(event.get("event_type", event.get("type", "")))


def _event_details(event: Mapping[str, Any]) -> Mapping[str, Any]:
    details = event.get("details")
    if isinstance(details, Mapping) and isinstance(details.get("value"), Mapping):
        return details["value"]
    return details if isinstance(details, Mapping) else event


def _assessment(state: Mapping[str, Any], artifact: Mapping[str, Any], *, as_of: datetime | None = None) -> dict[str, Any]:
    """Derive assessment from immutable artifact data and append-only events."""
    instant = as_of or _now()
    events = _calibration_events(state, str(artifact.get("id")))
    invalidations = [event for event in events if _event_type(event) == "invalidated"]
    supersessions = [event for event in events if _event_type(event) == "superseded"]
    if invalidations:
        return {"artifact_id": artifact.get("id"), "status": "invalid", "active": False,
                "assessed_at": _iso(instant), "reasons": [str(invalidations[-1].get("reason", "invalidated"))]}
    if supersessions:
        target = _event_details(supersessions[-1]).get("superseding_artifact_id")
        return {"artifact_id": artifact.get("id"), "status": "invalid", "active": False,
                "assessed_at": _iso(instant), "reasons": [f"superseded_by:{target}"]}
    if artifact.get("source_type") == "operator_assumed_fixture" or artifact.get("purpose") == "test_fixture":
        return {"artifact_id": artifact.get("id"), "status": "fixture_only", "active": False,
                "assessed_at": _iso(instant), "reasons": ["fixture_provenance_not_physical_calibration"]}
    policy = artifact.get("validity_policy") if isinstance(artifact.get("validity_policy"), Mapping) else {}
    max_age = policy.get("max_age_seconds")
    if max_age is None and isinstance(policy.get("max_age_days"), (int, float)):
        max_age = float(policy["max_age_days"]) * 86400
    performed = _parse_time(artifact.get("performed_at") or artifact.get("created_at"))
    if isinstance(max_age, (int, float)) and instant >= performed + timedelta(seconds=float(max_age)):
        return {"artifact_id": artifact.get("id"), "status": "stale", "active": False,
                "assessed_at": _iso(instant), "reasons": ["validity_policy_expired"]}
    return {"artifact_id": artifact.get("id"), "status": "valid", "active": True,
            "assessed_at": _iso(instant), "reasons": []}


def _distribution_rows(state: Mapping[str, Any], artifact: Mapping[str, Any], *, controller_id: str | None = None) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for event in _calibration_events(state, str(artifact.get("id"))):
        details = _event_details(event)
        target, command_id = details.get("controller_id"), details.get("command_id")
        if not isinstance(target, str) or not isinstance(command_id, str) or (controller_id and target != controller_id):
            continue
        row = rows.setdefault(command_id, {"artifact_id": artifact.get("id"), "artifact_digest": artifact.get("artifact_digest"),
                                           "controller_id": target, "controller_generation": details.get("controller_generation"),
                                           "command_id": command_id, "state": "pending", "requested_at": None})
        if _event_type(event) == "distribution_requested":
            row["requested_at"] = event.get("occurred_at", event.get("at")); row["request_id"] = details.get("request_id")
        elif _event_type(event) == "distribution_stored":
            row.update({"state": "stored", "stored_at": event.get("occurred_at", event.get("at"))})
        elif _event_type(event) == "distribution_failed":
            row.update({"state": "failed", "failure_reason": event.get("reason")})
    return list(rows.values())


def _artifact_projection(state: Mapping[str, Any], artifact: Mapping[str, Any], *, as_of: datetime | None = None) -> dict[str, Any]:
    result = copy.deepcopy(dict(artifact))
    result.pop("assessment", None); result.pop("distribution", None)
    result["assessment"] = _assessment(state, artifact, as_of=as_of)
    result["distributions"] = _distribution_rows(state, artifact)
    return result


def _calibration_rows(state: dict[str, Any], *, instrument_id: str | None = None) -> list[dict[str, Any]]:
    rows = []
    for artifact in state.get("calibration_artifacts", {}).values():
        if not isinstance(artifact, dict) or _assessment(state, artifact)["status"] not in {"valid", "stale", "fixture_only"}:
            continue
        if instrument_id is not None and artifact.get("instrument_id") != instrument_id:
            continue
        rows.append(_artifact_projection(state, artifact))
    return rows


def _calibration_requirements(instrument: Mapping[str, Any]) -> dict[str, str]:
    """Map verified edge capabilities to the calibration artifact they require."""
    defaults = {"temperature_read": "temperature", "heater_control": "temperature",
                "od_read": "optical_density", "pump_control": "pump_flow_rate"}
    result: dict[str, str] = {}
    capabilities = instrument.get("capabilities") if isinstance(instrument.get("capabilities"), Mapping) else {}
    for capability, detail in capabilities.items():
        if not isinstance(capability, str):
            continue
        declared = detail.get("calibration_type") if isinstance(detail, Mapping) else None
        required = bool(isinstance(detail, Mapping) and (detail.get("requires_calibration") or detail.get("calibration_required")))
        calibration_type = declared if isinstance(declared, str) else defaults.get(capability)
        if calibration_type and (required or capability in defaults):
            result[capability] = calibration_type
    return result


def _calibration_readiness(state: Mapping[str, Any], controller_id: str,
                           controller_generation: Any, instrument: Mapping[str, Any]) -> dict[str, Any]:
    requirements = _calibration_requirements(instrument)
    vials = instrument.get("vial_positions") if isinstance(instrument.get("vial_positions"), list) else []
    rows = []
    for vial in vials:
        vial_id = vial.get("id") if isinstance(vial, Mapping) else vial
        capabilities = []
        for capability, calibration_type in requirements.items():
            candidates = [artifact for artifact in state.get("calibration_artifacts", {}).values()
                          if isinstance(artifact, Mapping) and artifact.get("instrument_id") == instrument.get("id")
                          and artifact.get("vial_position_id") == vial_id and artifact.get("calibration_type") == calibration_type
                          and _assessment(state, artifact)["status"] == "valid"]
            candidate = max(candidates, key=lambda item: str(item.get("created_at", "")), default=None)
            distribution = next((row for row in _distribution_rows(state, candidate, controller_id=controller_id)
                                 if row.get("state") == "stored" and row.get("controller_generation") == controller_generation), None) if candidate else None
            capabilities.append({"capability": capability, "calibration_type": calibration_type,
                                 "state": "ready" if distribution else "calibration_required",
                                 "artifact_id": candidate.get("id") if candidate else None,
                                 "artifact_digest": candidate.get("artifact_digest") if candidate else None,
                                 "distribution": distribution})
        rows.append({"vial_position_id": vial_id,
                     "state": "ready" if all(item["state"] == "ready" for item in capabilities) else "calibration_required",
                     "capabilities": capabilities})
    ready = sum(1 for row in rows if row["state"] == "ready")
    return {"state": "ready" if ready == len(rows) else "calibration_required",
            "required_capabilities": requirements, "vials": rows,
            "ready_vial_count": ready, "total_vial_count": len(rows)}


def calibrations(*, calibration_id: str | None = None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    with _LOCK:
        state = _state(state_path(state_root))
        rows = []
        for session in state.get("calibration_sessions", {}).values():
            if isinstance(session, dict): rows.append({**copy.deepcopy(session), "record_kind": "session"})
        for artifact in state.get("calibration_artifacts", {}).values():
            if isinstance(artifact, dict): rows.append({**_artifact_projection(state, artifact), "record_kind": "artifact"})
        if calibration_id is not None:
            found = next((item for item in rows if item.get("id") == calibration_id), None)
            return (HTTPStatus.OK, {"calibration": found, "webui_controller": _response_identity(state)}) if found else (HTTPStatus.NOT_FOUND, _error("calibration not found", "NotFound", state))
        return HTTPStatus.OK, {"calibrations": sorted(rows, key=lambda item: str(item.get("created_at", "")), reverse=True), "firmware_supported_procedures": sorted(FIRMWARE_SUPPORTED_PROCEDURES), "webui_controller": _response_identity(state)}


def calibration_workspace(*, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Bounded aggregate used by every calibration workspace surface."""
    status, calibration_payload = calibrations(state_root=state_root)
    if status != HTTPStatus.OK:
        return status, calibration_payload
    instrument_payload = instruments(state_root=state_root)[1]
    return HTTPStatus.OK, {
        "calibrations": calibration_payload.get("calibrations", []),
        "instruments": instrument_payload.get("instruments", []),
        "firmware_supported_procedures": calibration_payload.get("firmware_supported_procedures", []),
        "webui_controller": calibration_payload.get("webui_controller"),
    }


def _instrument_exists(state: dict[str, Any], instrument_id: str) -> bool:
    return any(isinstance(item, dict) and item.get("id") == instrument_id for controller in state.get("controllers", {}).values() if isinstance(controller, dict) for item in controller.get("inventory", []))

def _instrument(state: dict[str, Any], instrument_id: str) -> dict[str, Any] | None:
    return next((item for controller in state.get("controllers", {}).values() if isinstance(controller, dict) for item in controller.get("inventory", []) if isinstance(item, dict) and item.get("id") == instrument_id), None)

def _vial_belongs(instrument: Mapping[str, Any], vial_position_id: str) -> bool:
    return any((item.get("id") if isinstance(item, dict) else item) == vial_position_id for item in instrument.get("vial_positions", []) if isinstance(item, (dict, str)))


def create_calibration_session(body: Any, *, operator: OperatorIdentity | None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_calibration")
    if denied: return denied
    if not isinstance(body, dict) or body.get("calibration_type") not in EVIDENCE_TYPES or not isinstance(body.get("instrument_id"), str): return HTTPStatus.BAD_REQUEST, _error("calibration_type and instrument_id are required")
    with _LOCK:
        path = state_path(state_root); state = _state(path)
        instrument = _instrument(state, body["instrument_id"])
        if instrument is None: return HTTPStatus.NOT_FOUND, _error("instrument not found", "NotFound", state)
        vial_position_id = body.get("vial_position_id", body.get("vial_position"))
        positions = instrument.get("vial_positions", [])
        if vial_position_id is None and positions: vial_position_id = positions[0].get("id") if isinstance(positions[0], dict) else positions[0]
        if body["calibration_type"] == "pump_flow_rate" and not isinstance(body.get("component_id"), str):
            return HTTPStatus.BAD_REQUEST, _error("pump flow calibration requires component_id", "InvalidCalibrationTarget", state)
        if body["calibration_type"] != "pump_flow_rate" and positions and (not isinstance(vial_position_id, str) or not _vial_belongs(instrument, vial_position_id)):
            return HTTPStatus.BAD_REQUEST, _error("vial_position_id must belong to the instrument", "InvalidCalibrationTarget", state)
        session_id = f"calibration-session-{uuid.uuid4()}"
        session = {"id": session_id, "calibration_type": body["calibration_type"], "instrument_id": body["instrument_id"], "component_id": body.get("component_id"), "vial_position_id": vial_position_id, "vial_position": vial_position_id, "operator": operator.subject, "created_at": _iso(), "started_at": _iso(), "method": body.get("method") or body["calibration_type"], "observations": [], "state": "collecting", "notes": body.get("notes")}
        state["calibration_sessions"][session_id] = session
        _write(path, state)
        return HTTPStatus.CREATED, {"session": copy.deepcopy(session), "webui_controller": _response_identity(state)}


def calibration_session_mutation(session_id: str, action: str, body: Any, *, operator: OperatorIdentity | None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_calibration")
    if denied: return denied
    with _LOCK:
        path = state_path(state_root); state = _state(path); session = state.get("calibration_sessions", {}).get(session_id)
        if not isinstance(session, dict): return HTTPStatus.NOT_FOUND, _error("calibration session not found", "NotFound", state)
        if session.get("state") in {"completed", "cancelled", "rejected"} and action != "accept": return HTTPStatus.CONFLICT, _error("terminal calibration sessions are immutable", "CalibrationSessionImmutable", state)
        if action == "observation":
            if not isinstance(body, dict): return HTTPStatus.BAD_REQUEST, _error("observation body must be an object")
            try: typed = validate_observation(session["calibration_type"], body)
            except ValueError as exc: return HTTPStatus.BAD_REQUEST, _error(str(exc), "InvalidCalibrationObservation", state)
            observation = {**typed, "id": f"observation-{uuid.uuid4()}", "sequence": len(session["observations"]) + 1, "vial_position_id": session["vial_position_id"], "vial_position": session["vial_position_id"], "raw_metric": typed.get("raw_metric", "adc"), "raw_unit": typed.get("raw_unit", "ADC"), "captured_at": typed.get("captured_at", _iso()), "source_type": typed.get("source_type", "manual"), "source_record_id": typed.get("source_record_id"), "operator_note": typed.get("operator_note")}
            session["observations"].append(observation); session["state"] = "review"
        elif action == "fit":
            try: session["candidate"] = calculate_candidate(session["calibration_type"], session.get("observations", []))
            except ValueError as exc: return HTTPStatus.UNPROCESSABLE_ENTITY, _error(str(exc), "UnsupportedCalibrationMethod")
            session["state"] = "ready_to_accept"
        elif action == "cancel":
            try: session.update(transition_session(session, "cancelled"))
            except CalibrationConflictError as exc: return HTTPStatus.CONFLICT, _error(str(exc), "CalibrationSessionConflict", state)
            session["completed_at"] = _iso()
        elif action == "accept":
            candidate = session.get("candidate")
            if session.get("state") != "ready_to_accept" or not isinstance(candidate, dict): return HTTPStatus.CONFLICT, _error("calculate a supported candidate before acceptance", "CalibrationNotReady")
            artifact_id = f"calibration-artifact-{uuid.uuid4()}"
            source_digest = digest(session.get("observations", []))
            artifact = {"id": artifact_id, "calibration_type": session["calibration_type"], "instrument_id": session["instrument_id"], "component_id": session.get("component_id"), "vial_position_id": session["vial_position_id"], "vial_position": session["vial_position_id"], "method": candidate["method"], "method_version": candidate["method_version"], "coefficients": copy.deepcopy(candidate["coefficients"]), "fit_diagnostics": copy.deepcopy(candidate["fit_diagnostics"]), "calibration_range": copy.deepcopy(candidate.get("calibration_range", {})), "observations": copy.deepcopy(session["observations"]), "source_data_digest": source_digest, "evidence_digest": source_digest, "hardware_fingerprint": body.get("hardware_fingerprint") if isinstance(body, dict) else None, "performed_at": _iso(), "performed_by": operator.subject, "created_at": _iso(), "validity_policy": {"max_age_days": 180}, "artifact_digest": ""}
            artifact["artifact_digest"] = digest({key: value for key, value in artifact.items() if key != "artifact_digest"})
            state["calibration_artifacts"][artifact_id] = artifact; session.update(transition_session(session, "completed")); session["accepted_artifact_id"] = artifact_id; session["completed_at"] = _iso()
            state["calibration_events"].append(_calibration_event(
                "accepted", artifact_id, actor=operator.subject,
                details={"session_id": session_id}, session_id=session_id,
            ))
            _write(path, state)
            return HTTPStatus.CREATED, {"artifact": _artifact_projection(state, artifact), "session": copy.deepcopy(session), "webui_controller": _response_identity(state)}
        else: return HTTPStatus.BAD_REQUEST, _error("unknown calibration session action")
        _write(path, state)
        return HTTPStatus.OK, {"session": copy.deepcopy(session), "webui_controller": _response_identity(state)}


def create_pump_fixture_artifacts(instrument_id: str, records: list[Any] | None = None, *, operator: OperatorIdentity | None,
                                  state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Persist real operator fixture records without claiming physical calibration."""
    denied = _require_operator(operator, "manage_calibration")
    if denied:
        return denied
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        instrument = _instrument(state, instrument_id)
        if instrument is None:
            return HTTPStatus.NOT_FOUND, _error("instrument not found", "NotFound", state)
        if not isinstance(records, list) or len(records) != 6:
            return HTTPStatus.BAD_REQUEST, _error("exactly six pump fixture records (P0-P5) are required", "InvalidFixtureRecords", state)
        by_component: dict[str, Mapping[str, Any]] = {}
        for supplied in records:
            if not isinstance(supplied, Mapping):
                return HTTPStatus.BAD_REQUEST, _error("pump fixture records must be objects", "InvalidFixtureRecords", state)
            component = supplied.get("component_id", supplied.get("component", supplied.get("channel")))
            if isinstance(component, int):
                component = f"P{component}"
            if not isinstance(component, str) or component not in {f"P{i}" for i in range(6)} or component in by_component:
                return HTTPStatus.BAD_REQUEST, _error("fixture records must bind uniquely to P0-P5", "InvalidFixtureBinding", state)
            supplied_channel = supplied.get("channel_index", supplied.get("channel"))
            if supplied_channel is not None and supplied_channel != int(component[1:]):
                return HTTPStatus.BAD_REQUEST, _error("fixture component and channel binding disagree", "InvalidFixtureBinding", state)
            by_component[component] = supplied
        existing = [item for item in state.setdefault("calibration_artifacts", {}).values()
                    if isinstance(item, dict) and item.get("instrument_id") == instrument_id
                    and item.get("method") == "pump_flow_fixture_v1"]
        latest_by_component: dict[str, Mapping[str, Any]] = {}
        for item in existing:
            component = item.get("component_id")
            if isinstance(component, str):
                latest_by_component[component] = item
        matching_by_component = {
            component: max((item for item in existing
                            if item.get("component_id") == component
                            and item.get("fixture_record") == dict(supplied)
                            and isinstance(item.get("coefficients"), Mapping)
                            and math.isclose(float(item["coefficients"].get("flow_ml_per_min")),
                                             float(supplied["delivered_volume_ul"]) / float(supplied["pulse_duration_ms"]) * 60,
                                             rel_tol=1e-9, abs_tol=1e-9)),
                           key=lambda item: str(item.get("created_at", "")), default=None)
            for component, supplied in by_component.items()
        }
        if all(isinstance(item, Mapping) for item in matching_by_component.values()):
            return HTTPStatus.OK, {"artifacts": [copy.deepcopy(matching_by_component[component]) for component in by_component],
                                   "idempotent": True, "webui_controller": _response_identity(state)}
        artifacts = []
        for component_id, supplied in by_component.items():
            try:
                duration = float(supplied["pulse_duration_ms"])
                volume = float(supplied["delivered_volume_ul"])
            except (KeyError, TypeError, ValueError) as exc:
                return HTTPStatus.BAD_REQUEST, _error("fixture records require pulse_duration_ms and delivered_volume_ul", "InvalidFixtureRecords", state)
            if duration <= 0 or volume < 0 or not math.isfinite(duration + volume):
                return HTTPStatus.BAD_REQUEST, _error("fixture duration must be positive and volume finite", "InvalidFixtureRecords", state)
            # ul/ms is numerically ml/s; convert seconds to minutes.
            rate = volume / duration * 60
            artifact_id = f"calibration-artifact-fixture-{uuid.uuid4()}"
            artifact = {"id": artifact_id, "calibration_type": "pump_flow_rate", "instrument_id": instrument_id,
                         "component_id": pump_component(component_id), "channel_index": int(component_id[1:]),
                         "vial_position_id": None, "method": "pump_flow_fixture_v1",
                         "method_version": "1", "coefficients": {"flow_ml_per_min": rate},
                         "fit_diagnostics": {"observations": 1, "verification": "fixture_record"},
                         "calibration_range": {}, "evidence_digest": digest(dict(supplied)),
                         "artifact_digest": "", "performed_at": _iso(), "performed_by": operator.subject,
                         "created_at": _iso(), "validity_policy": {"supersedable": True},
                         "verification": "assumed", "source_type": "operator_assumed_fixture", "purpose": "test_fixture",
                         "physical_verification": "not_tested", "calibration_status": "fixture_only",
                         "physical_calibration_status": "not_calibrated",
                         "fixture_provenance": {"source": "operator_assumed_fixture", "status": "assumed",
                                                "physical_calibration": "not_verified"},
                         "fixture_status": "assumed", "is_physical_calibration": False,
                         "fixture_record": copy.deepcopy(dict(supplied)),
                         "observations": [copy.deepcopy(dict(supplied))]}
            artifact["artifact_digest"] = digest({key: value for key, value in artifact.items() if key != "artifact_digest"})
            state["calibration_artifacts"][artifact_id] = artifact
            artifacts.append(artifact)
        for artifact in artifacts:
            component = artifact["component_id"]
            prior = latest_by_component.get(component)
            if not isinstance(prior, Mapping) or prior.get("id") == artifact["id"]:
                continue
            if any(_event_type(event) == "superseded" for event in _calibration_events(state, str(prior["id"]))):
                continue
            state.setdefault("calibration_events", []).append(_calibration_event(
                "superseded", str(prior["id"]), actor=operator.subject,
                details={"superseding_artifact_id": artifact["id"]},
                superseding_artifact_id=artifact["id"],
            ))
        _audit(state, "pump_fixture_calibrations_created", actor=operator.subject,
               details={"instrument_id": instrument_id, "artifact_ids": [item["id"] for item in artifacts]})
        _write(path, state)
        return HTTPStatus.CREATED, {"artifacts": copy.deepcopy(artifacts), "webui_controller": _response_identity(state)}


def deliver_calibration_artifact(artifact_id: str, *, operator: OperatorIdentity | None,
                                 request_id: str | None = None,
                                 state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_calibration")
    if denied: return denied
    with _LOCK:
        path = state_path(state_root); state = _state(path); artifact = state.get("calibration_artifacts", {}).get(artifact_id)
        if not isinstance(artifact, dict): return HTTPStatus.NOT_FOUND, _error("calibration artifact not found", "NotFound", state)
        if _assessment(state, artifact)["status"] != "valid": return HTTPStatus.CONFLICT, _error("only a valid artifact may be distributed", "CalibrationNotDistributable", state)
        active = {"running", "paused", "stopping"}; active_runs = []
        for controller in state.get("controllers", {}).values():
            summary = controller.get("recovery_summary") or controller.get("recovery_manifest") or {} if isinstance(controller, Mapping) else {}
            for run in summary.get("runs", []) if isinstance(summary, Mapping) else []:
                if isinstance(run, Mapping) and run.get("state") in active and artifact.get("instrument_id") in run.get("instrument_ids", []): active_runs.append(str(run.get("id")))
        if active_runs: return HTTPStatus.CONFLICT, _error("cannot distribute calibration while a target run is active", "CalibrationDistributionUnsafe", state, active_run_ids=active_runs)
        target = next(((controller_id, controller) for controller_id, controller in state["controllers"].items() if isinstance(controller, dict) and any(isinstance(item, dict) and item.get("id") == artifact.get("instrument_id") for item in controller.get("inventory", []))), None)
        if target is None: return HTTPStatus.CONFLICT, _error("artifact target controller is unavailable", "CalibrationDistributionPending", state)
        controller_id, controller = target; generation = controller["binding"]["controller_generation"]
        existing = [command for command in state["commands"].setdefault(controller_id, []) if isinstance(command, dict) and command.get("artifact_id") == artifact_id and command.get("artifact_digest") == artifact.get("artifact_digest") and command.get("controller_generation") == generation]
        distributions = _distribution_rows(state, artifact, controller_id=controller_id)
        if request_id is not None:
            prior = next((row for row in distributions if row.get("request_id") == request_id), None)
            if prior is not None:
                command = next((item for item in existing if item.get("command_id") == prior.get("command_id")), None)
                response: dict[str, Any] = {"distribution": copy.deepcopy(prior), "idempotent": True,
                                             "webui_controller": _response_identity(state)}
                if isinstance(command, dict):
                    response["command"] = {key: value for key, value in command.items() if key != "payload"}
                return HTTPStatus.OK, response
        if any(row.get("state") == "stored" for row in distributions): return HTTPStatus.OK, {"distribution": next(row for row in distributions if row.get("state") == "stored"), "webui_controller": _response_identity(state)}
        pending = next((command for command in existing if command.get("disposition") not in _TERMINAL_COMMAND_DISPOSITIONS), None)
        if pending is not None: return HTTPStatus.ACCEPTED, {"command": {key: value for key, value in pending.items() if key != "payload"}, "distribution": {"state": "pending", "artifact_id": artifact_id}, "webui_controller": _response_identity(state)}
        command = {"command_id": f"command-{uuid.uuid4()}", "controller_generation": generation, "command_kind": "store_calibration_artifact", "artifact_id": artifact_id, "artifact_digest": artifact.get("artifact_digest"), "instrument_id": artifact["instrument_id"], "vial_position_id": artifact.get("vial_position_id"), "vial_position": artifact.get("vial_position_id"), "payload": copy.deepcopy(artifact), "requested_at": _iso(), "requested_by": operator.subject, "disposition": "queued"}
        state["commands"].setdefault(controller_id, []).append(command)
        request_details = {"command_id": command["command_id"], "controller_id": controller_id,
                           "controller_generation": generation, "artifact_digest": artifact["artifact_digest"]}
        if request_id is not None:
            request_details["request_id"] = request_id
            command["request_id"] = request_id
        state.setdefault("calibration_events", []).append(_calibration_event("distribution_requested", artifact_id, actor=operator.subject, details=request_details))
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"command": {key: value for key, value in command.items() if key != "payload"}, "distribution": _distribution_rows(state, artifact, controller_id=controller_id)[-1], "webui_controller": _response_identity(state)}


def supersede_calibration_artifact(artifact_id: str, *, superseding_artifact_id: str,
                                   operator: OperatorIdentity | None,
                                   state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Append a supersession fact; immutable artifact rows are never rewritten."""
    denied = _require_operator(operator, "manage_calibration")
    if denied:
        return denied
    with _LOCK:
        path = state_path(state_root); state = _state(path)
        artifact = state.get("calibration_artifacts", {}).get(artifact_id)
        replacement = state.get("calibration_artifacts", {}).get(superseding_artifact_id)
        if not isinstance(artifact, dict) or not isinstance(replacement, dict):
            return HTTPStatus.NOT_FOUND, _error("calibration artifact not found", "NotFound", state)
        if artifact_id == superseding_artifact_id:
            return HTTPStatus.BAD_REQUEST, _error("an artifact cannot supersede itself", "InvalidSupersession", state)
        prior = next((event for event in _calibration_events(state, artifact_id)
                      if _event_type(event) == "superseded"), None)
        if prior is None:
            state.setdefault("calibration_events", []).append(_calibration_event(
                "superseded", artifact_id, actor=operator.subject,
                details={"superseding_artifact_id": superseding_artifact_id},
                superseding_artifact_id=superseding_artifact_id,
            ))
            _write(path, state)
        return HTTPStatus.OK, {"artifact": _artifact_projection(state, artifact),
                               "webui_controller": _response_identity(state)}

def invalidate_calibration_artifact(artifact_id: str, *, reason: str, operator: OperatorIdentity | None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_calibration")
    if denied: return denied
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root)); artifact = state.get("calibration_artifacts", {}).get(artifact_id)
        if not isinstance(artifact, dict): return HTTPStatus.NOT_FOUND, _error("calibration artifact not found", "NotFound", state)
        state.setdefault("calibration_events", []).append(_calibration_event("invalidated", artifact_id, actor=operator.subject, reason=reason, details={"reason": reason}))
        _write(path, state); return HTTPStatus.OK, {"artifact": _artifact_projection(state, artifact), "webui_controller": _response_identity(state)}

def capture_latest_observation(session_id: str, body: Any, *, operator: OperatorIdentity | None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_calibration")
    if denied: return denied
    if not isinstance(body, dict) or not isinstance(body.get("reference_value"), (int, float)): return HTTPStatus.BAD_REQUEST, _error("reference_value is required")
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root)); session = state.get("calibration_sessions", {}).get(session_id)
        if not isinstance(session, dict): return HTTPStatus.NOT_FOUND, _error("calibration session not found", "NotFound", state)
        metric = body.get("raw_metric", "thermistor_raw"); candidates = [row for controller_id, controller in state.get("controllers", {}).items() if isinstance(controller, dict) for row in _normalized_telemetry(controller_id, controller.get("telemetry", [])) if row.get("instrument_id") == session.get("instrument_id") and row.get("vial_position_id") == session.get("vial_position_id") and row.get("metric") == metric and isinstance(row.get("value"), (int, float))]
        if not candidates: return HTTPStatus.NOT_FOUND, _error("no matching raw telemetry is available", "RawTelemetryUnavailable", state)
        raw = candidates[-1]; captured_at = raw.get("captured_at") or _iso()
        try:
            age_seconds = (_now() - _parse_time(captured_at)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return HTTPStatus.CONFLICT, _error("raw telemetry timestamp is invalid", "RawTelemetryStale", state)
        if age_seconds > 60:
            return HTTPStatus.CONFLICT, _error("latest raw telemetry is older than 60 seconds; refresh before capture", "RawTelemetryStale", state, age_seconds=age_seconds)
        observation = {"raw_value": raw["value"], "raw_unit": "ADC", "reference_value": body["reference_value"], "reference_unit": body.get("reference_unit", "°C"), "raw_metric": metric, "captured_at": captured_at, "source_type": "central_telemetry", "source_record_id": f"{raw.get('stream_id')}:{raw.get('sequence')}", "source_provenance": {"controller_id": raw.get("controller_id"), "instrument_id": raw.get("instrument_id"), "vial_position_id": raw.get("vial_position_id"), "stream_id": raw.get("stream_id"), "sequence": raw.get("sequence"), "age_seconds": age_seconds}, "reference_value": body["reference_value"]}
    return calibration_session_mutation(session_id, "observation", observation, operator=operator, state_root=state_root)


def _active_temperature_artifact(state: Mapping[str, Any], raw: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Select one exact, current artifact for a raw thermistor observation."""
    candidates: list[Mapping[str, Any]] = []
    for artifact in state.get("calibration_artifacts", {}).values():
        if not isinstance(artifact, Mapping) or artifact.get("calibration_type") != "temperature":
            continue
        if _assessment(state, artifact)["status"] != "valid":
            continue
        if artifact.get("instrument_id") != raw.get("instrument_id") or artifact.get("vial_position_id") != raw.get("vial_position_id"):
            continue
        raw_component = raw.get("component_id")
        artifact_component = artifact.get("component_id")
        if raw_component is not None and artifact_component != raw_component:
            continue
        if raw_component is None and artifact_component is not None:
            continue
        distribution = {row.get("controller_id"): row for row in _distribution_rows(state, artifact)}
        if not distribution and isinstance(artifact.get("distribution"), Mapping):
            distribution = artifact["distribution"]
        controller_id = raw.get("controller_id")
        if controller_id and isinstance(distribution, Mapping):
            delivered = distribution.get(controller_id)
            if not isinstance(delivered, Mapping) or delivered.get("state") != "stored":
                continue
            controller = state.get("controllers", {}).get(controller_id)
            if isinstance(controller, Mapping) and delivered.get("controller_generation") != controller.get("binding", {}).get("controller_generation"):
                continue
        candidates.append(artifact)
    return max(candidates, key=lambda item: str(item.get("created_at", "")), default=None)


def _calibrated_telemetry(state: Mapping[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = list(rows)
    for raw in rows:
        if raw.get("metric") != "thermistor_raw":
            continue
        artifact = _active_temperature_artifact(state, raw)
        if artifact is None:
            continue
        derived = derive_temperature(raw, artifact)
        if derived is not None:
            result.append({**derived, "controller_id": raw.get("controller_id"), "channel_index": raw.get("channel_index"), "captured_at": raw.get("captured_at"), "source": "central_calibration"})
    return result


def instruments(*, instrument_id: str | None = None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Return the edge-reported physical/simulated inventory without raw telemetry.

    Instruments deliberately remain projections: slot identity comes from the
    controller inventory, never from a sample label or a serial device path.
    Raw sensor batches stay on the bounded telemetry API/sync path rather than
    being accidentally made unbounded by this fleet page.
    """
    with _LOCK:
        state = _state(state_path(state_root))
        projected: list[dict[str, Any]] = []
        for controller_id, controller in state["controllers"].items():
            if not isinstance(controller, dict):
                continue
            inventory = controller.get("inventory", [])
            if not isinstance(inventory, list):
                continue
            for item in inventory:
                if isinstance(item, dict) and isinstance(item.get("id"), str):
                    public = copy.deepcopy(item)
                    public["name"] = _display_name(state, "instruments", item["id"], public.get("name"))
                    public["controller_id"] = controller_id
                    public["controller_connection_state"] = controller.get("connection_state", "unknown")
                    positions = public.get("vial_positions") if isinstance(public.get("vial_positions"), list) else []
                    public["calibration_readiness"] = _calibration_readiness(
                        state, controller_id,
                        controller.get("binding", {}).get("controller_generation"),
                        public,
                    )
                    assigned = [run for run in (runs(state_root=state_root)[1].get("runs", [])) if public["id"] in (run.get("instrument_ids") or []) and run.get("state") not in {"completed", "stopped", "failed"}]
                    occupied = min(len(assigned), len(positions))
                    commissioning = str(public.get("commissioning_state", "")).lower()
                    verification = str(public.get("verification", "")).lower()
                    calibration = public.get("calibration") if isinstance(public.get("calibration"), dict) else {}
                    calibrated = calibration.get("state") in {"calibrated", "valid", "verified"} or public.get("calibration_state") in {"calibrated", "valid", "verified"}
                    artifacts = _calibration_rows(state, instrument_id=public["id"])
                    pump_artifacts = {str(item.get("component_id")): item for item in artifacts
                                      if item.get("calibration_type") == "pump_flow_rate"
                                      and item.get("method") == "pump_flow_fixture_v1"}
                    public["pumps"] = [{"id": f"P{index}", "label": f"P{index}",
                                        "state": "idle", "physically_commissioned": False,
                                        **({"fixture_rate": item.get("coefficients", {}).get("flow_ml_per_min"),
                                            "verification": "fixture_assumed", "calibration_artifact": item}
                                            if (item := pump_artifacts.get(f"P{index}")) else {})}
                                       for index in range(6)]
                    latest = _normalized_telemetry(controller_id, controller.get("telemetry", []))
                    public["telemetry"] = [{"metric": row.get("metric"), "value": row.get("value"),
                                            "unit": row.get("unit"), "captured_at": row.get("captured_at"),
                                            "vial_position_id": row.get("vial_position_id")}
                                           for row in latest if row.get("instrument_id") == public["id"]][-12:]
                    for position in positions:
                        position_id = position.get("id") if isinstance(position, dict) else position
                        readings = [row for row in latest if row.get("instrument_id") == public["id"] and row.get("vial_position_id") == position_id]
                        if isinstance(position, dict):
                            for metric, key in (("thermistor_raw", "raw_temperature_adc"), ("photodiode_raw", "raw_photodiode_adc")):
                                values = [row.get("value") for row in readings if row.get("metric") == metric]
                                if values:
                                    position[key] = values[-1]
                    calibration_types = {str(item.get("calibration_type")) for item in artifacts if item.get("assessment", {}).get("status") == "valid"}
                    if artifacts:
                        public["calibration"] = {"state": "valid" if calibration_types else "missing", "types": {kind: ("valid" if kind in calibration_types else "missing") for kind in ("temperature", "optical_density")}, "artifacts": [{"id": item.get("id"), "digest": item.get("artifact_digest"), "type": item.get("calibration_type"), "status": item.get("assessment", {}).get("status")} for item in artifacts]}
                        calibrated = {"temperature", "optical_density"}.issubset(calibration_types)
                    connected = public.get("connection_state", controller.get("connection_state")) == "connected"
                    reasons = [] if connected else ["disconnected"]
                    if commissioning not in {"ready", "commissioned"}: reasons.append("commissioning")
                    if verification in {"failed", "verification_failed"}: reasons.append("verification_failed")
                    if not calibrated: reasons.append("calibration_required")
                    ready = len(positions) if connected and not reasons else occupied
                    state_name = "ready" if ready == len(positions) else ("running" if occupied else (reasons[0] if reasons else "unavailable"))
                    public["readiness"] = {"state": state_name, "reasons": reasons}
                    public["capacity"] = {"occupied": occupied, "ready": max(occupied, min(ready, len(positions))), "total": len(positions)}
                    projected.append(public)
        projected.sort(key=lambda item: (str(item.get("controller_id")), str(item.get("id"))))
        if instrument_id is not None:
            found = next((item for item in projected if item["id"] == instrument_id), None)
            return (HTTPStatus.OK, {"instrument": found, "webui_controller": _response_identity(state)}) if found else (HTTPStatus.NOT_FOUND, _error("instrument not found", "NotFound", state))
        return HTTPStatus.OK, {"instruments": projected, "webui_controller": _response_identity(state)}


def dashboard(*, range_name: str = "1h", state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Return the bounded operator read model for the eVOLVER landing page.

    The projection deliberately contains summaries only. Raw event and
    telemetry histories stay behind detail/readout APIs; a deployment may
    seed ``dashboard`` in its central store for richer queue and intervention
    records while older state continues to derive useful rows here.
    """
    with _LOCK:
        state = _state(state_path(state_root))
        seeded = state.get("dashboard") if isinstance(state.get("dashboard"), dict) else {}
        rows = copy.deepcopy(seeded)
        if not rows:
            instrument_rows = instruments(state_root=state_root)[1].get("instruments", [])
            run_rows = runs(state_root=state_root)[1].get("runs", [])
            controllers_by_id = {item.get("id"): item for item in state["controllers"].values() if isinstance(item, dict)}
            evolvers = []
            for item in instrument_rows:
                controller = controllers_by_id.get(item.get("controller_id"), {})
                assigned = [run for run in run_rows if item.get("id") in run.get("instrument_ids", []) and run.get("state") not in {"completed", "stopped", "failed"}]
                connection = item.get("connection_state") or controller.get("connection_state") or "unknown"
                last_contact = controller.get("last_sync_at")
                status = "offline" if connection in {"disconnected", "offline"} else ("running" if assigned else "idle")
                evolvers.append({**item, "name": item.get("name") or item.get("id"), "status": status,
                                 "current_experiment": assigned[0].get("id") if assigned else None,
                                 "capacity": {"occupied": (item.get("capacity", {}).get("occupied", 0) if isinstance(item.get("capacity"), dict) else 0),
                                               "ready": (item.get("capacity", {}).get("ready", 0) if isinstance(item.get("capacity"), dict) else 0),
                                               "total": (item.get("capacity", {}).get("total", len(item.get("vial_positions", []))) if isinstance(item.get("capacity"), dict) else len(item.get("vial_positions", [])))},
                                 "last_contact_at": last_contact})
            rows = {"evolvers": evolvers, "experiments": run_rows, "deployments": [], "interventions": [], "telemetry": []}
        rows.setdefault("evolvers", []); rows.setdefault("experiments", [])
        rows.setdefault("deployments", copy.deepcopy(state.get("deployments", [])))
        rows.setdefault("interventions", list(copy.deepcopy(state.get("interventions", {})).values()) if isinstance(state.get("interventions"), dict) else [])
        if not rows.get("telemetry"):
            rows["telemetry"] = [record for controller_id, controller in state["controllers"].items()
                                  if isinstance(controller, dict) for record in _normalized_telemetry(controller_id, controller.get("telemetry", []))]
        else:
            normalized = []
            for record in rows["telemetry"]:
                normalized.extend(_normalized_telemetry(str(record.get("controller_id", "seed")), [record]) if isinstance(record, dict) else [])
            rows["telemetry"] = normalized or rows["telemetry"]
        rows["telemetry"] = _calibrated_telemetry(state, rows["telemetry"])
        # DeploymentQueueEntry is the queue authority. Enrich experiment
        # projections from it instead of trusting duplicated ad-hoc fields.
        deployments = [item for item in rows["deployments"] if isinstance(item, dict)]
        by_run = {str(item.get("experiment_run_id")): item for item in deployments}
        for experiment in rows["experiments"]:
            if not isinstance(experiment, dict):
                continue
            # Normalize the historical fixture spelling at this boundary;
            # browser and domain projections use LinkML names only.
            if "instrument_ids" not in experiment and "evolver_ids" in experiment:
                experiment["instrument_ids"] = experiment.pop("evolver_ids")
            entry = by_run.get(str(experiment.get("id")))
            if entry:
                experiment.update({key: copy.deepcopy(entry[key]) for key in ("queue_position", "status", "required_instrument_ids", "blockers", "queued_at") if key in entry})
        for intervention in rows["interventions"]:
            if not isinstance(intervention, dict):
                continue
            if "experiment_run_id" not in intervention and "experiment_id" in intervention:
                intervention["experiment_run_id"] = intervention.pop("experiment_id")
            if "instrument_id" not in intervention and "evolver_id" in intervention:
                intervention["instrument_id"] = intervention.pop("evolver_id")
        if range_name not in {"15m", "1h", "6h", "24h"}:
            return HTTPStatus.BAD_REQUEST, _error("range must be one of 15m, 1h, 6h, or 24h")
        # Seeded/demo projections may contain a bounded history. Filter it at
        # the read-model boundary so the browser never receives unlimited data.
        window_seconds = {"15m": 900, "1h": 3600, "6h": 21600, "24h": 86400}[range_name]
        cutoff = _now().timestamp() - window_seconds
        telemetry = []
        for item in rows["telemetry"]:
            if not isinstance(item, dict):
                continue
            timestamp = item.get("captured_at") or item.get("timestamp") or item.get("at")
            if timestamp is None or _parse_time(timestamp).timestamp() >= cutoff:
                telemetry.append(item)
        rows["telemetry"] = telemetry
        return HTTPStatus.OK, {**rows, "telemetry_window": range_name, "telemetry_window_seconds": window_seconds, "webui_controller": _response_identity(state)}


def complete_intervention(intervention_id: str, body: Any, *, operator: OperatorIdentity | None,
                          state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "operate_run")
    if denied:
        return denied
    with _LOCK:
        path = state_path(state_root); state = _state(path)
        interventions = state.setdefault("interventions", {})
        record = interventions.get(intervention_id)
        dashboard_intervention = None
        if not isinstance(record, dict):
            for item in state.get("dashboard", {}).get("interventions", []) if isinstance(state.get("dashboard"), dict) else []:
                if isinstance(item, dict) and item.get("id") == intervention_id:
                    record = item; dashboard_intervention = item; interventions[intervention_id] = record; break
        if not isinstance(record, dict):
            return HTTPStatus.NOT_FOUND, _error("intervention not found", "NotFound", state)
        if record.get("status") == "completed":
            return HTTPStatus.OK, {"intervention": copy.deepcopy(record), "idempotent": True, "webui_controller": _response_identity(state)}
        record.update({"status": "completed", "completed_at": _iso(), "completed_by": operator.subject})
        record.setdefault("events", []).append({"type": "intervention_completed", "occurred_at": record["completed_at"], "by": operator.subject})
        if dashboard_intervention is not None:
            dashboard_intervention.update(copy.deepcopy(record))
        _write(path, state)
        return HTTPStatus.OK, {"intervention": copy.deepcopy(record), "webui_controller": _response_identity(state)}


def maintenance(*, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Expose safe service/version/update observations for maintenance UI."""
    status, payload = controllers(state_root=state_root)
    if status is not HTTPStatus.OK:
        return status, payload
    state = _state(state_path(state_root))
    endpoint_assignments = state.get("endpoint_assignments", {})
    rows = []
    for controller in payload["controllers"]:
        heartbeat = controller.get("last_heartbeat") if isinstance(controller.get("last_heartbeat"), dict) else {}
        rows.append({
            "controller_id": controller.get("id"), "connection_state": controller.get("connection_state"),
            "last_sync_at": controller.get("last_sync_at"), "binding": controller.get("binding"),
            "software_release": heartbeat.get("controller_software_release"),
            "desired_release": controller.get("desired_release") or heartbeat.get("desired_controller_software_release"),
            "software_summary": f"{heartbeat.get('controller_software_release') or 'unknown'} → {controller.get('desired_release') or heartbeat.get('desired_controller_software_release') or 'none'}",
            "update_policy": heartbeat.get("update_policy"),
            "service_health": heartbeat.get("service_health", heartbeat.get("state")),
            "hardware_service_health": heartbeat.get("hardware_service_health"),
            "lifecycle_state": controller.get("lifecycle_state", "active"),
            "endpoint_assignment": copy.deepcopy(endpoint_assignments.get(controller.get("id"))) if isinstance(endpoint_assignments, Mapping) else None,
            "endpoint_id": (endpoint_assignments.get(controller.get("id"), {}) or {}).get("endpoint_id") if isinstance(endpoint_assignments, Mapping) else None,
            "inventory": controller.get("inventory", []),
        })
    return HTTPStatus.OK, {"maintenance": rows, "webui_controller": payload["webui_controller"]}


def configured_release_catalog(*, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Return the validated, immutable release manifests available to edges."""
    from . import evolver_release

    repository_root = Path(os.environ.get("META_WEBUI_REPOSITORY_ROOT", Path.cwd()))
    root = evolver_release.release_root(repository_root)
    releases: list[dict[str, Any]] = []
    if root.is_dir():
        for candidate in sorted(root.iterdir()):
            if not candidate.is_dir() or not evolver_release.RELEASE_ID_RE.fullmatch(candidate.name):
                continue
            try:
                manifest = evolver_release.manifest(repository_root, candidate.name)
            except (evolver_release.ReleaseError, FileNotFoundError):
                continue
            releases.append({"release": candidate.name, "version": manifest["version"],
                             "git_revision": manifest["git_revision"],
                             "protocol_version": manifest["protocol_version"],
                             "artifacts": copy.deepcopy(manifest["artifacts"]),
                             "firmware": copy.deepcopy(manifest.get("firmware"))})
    return HTTPStatus.OK, {"releases": releases,
                           "selected_release": os.environ.get("META_WEBUI_EVOLVER_RELEASE") or None}


def _active_run_ids(controller: Mapping[str, Any]) -> list[str]:
    summary = controller.get("recovery_summary") or controller.get("recovery_manifest") or {}
    runs = summary.get("runs", []) if isinstance(summary, Mapping) else []
    return [str(run.get("id")) for run in runs if isinstance(run, Mapping)
            and run.get("state") in {"running", "paused", "stopping"} and run.get("id")]


def set_desired_release(controller_id: str, body: Any, *, operator: OperatorIdentity | None,
                        state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Persist future software intent; installed software remains edge evidence."""
    denied = _require_operator(operator, "update_controller")
    if denied:
        return denied
    if not isinstance(body, dict) or not isinstance(body.get("release"), str):
        return HTTPStatus.BAD_REQUEST, _error("release is required")
    release = body["release"].strip()
    key = body.get("idempotency_key")
    if not release or not isinstance(key, (str, type(None))) or (isinstance(key, str) and not key.strip()):
        return HTTPStatus.BAD_REQUEST, _error("release and a valid idempotency_key are required")
    catalog_status, catalog = configured_release_catalog(state_root=state_root)
    if catalog_status is not HTTPStatus.OK or not any(item.get("release") == release for item in catalog["releases"]):
        return HTTPStatus.CONFLICT, _error("release is not a validated configured manifest", "ReleaseNotConfigured")
    with _LOCK:
        path = state_path(state_root); state = _state(path)
        controller = state["controllers"].get(controller_id)
        if not isinstance(controller, dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        if controller.get("lifecycle_state", "active") != "active":
            return HTTPStatus.CONFLICT, _error("archived controller cannot receive update intent", "ControllerArchived", state)
        if isinstance(key, str) and controller.get("desired_release_idempotency_key") == key:
            return HTTPStatus.OK, {"controller_id": controller_id, "desired_release": controller.get("desired_release"),
                                   "installed_release": (controller.get("last_heartbeat") or {}).get("controller_software_release"),
                                   "idempotent": True, "webui_controller": _response_identity(state)}
        controller.update({"desired_release": release, "desired_release_idempotency_key": key,
                           "desired_release_requested_at": _iso(), "desired_release_requested_by": operator.subject})
        _audit(state, "controller_desired_release_set", actor=operator.subject,
               details={"controller_id": controller_id, "release": release, "idempotency_key": key})
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"controller_id": controller_id, "desired_release": release,
                                     "installed_release": (controller.get("last_heartbeat") or {}).get("controller_software_release"),
                                     "deferred_to_edge_policy": True, "webui_controller": _response_identity(state)}


def archive_controller(controller_id: str, *, operator: OperatorIdentity | None,
                       state_root: Path | None = None, restore: bool = False) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_controller")
    if denied:
        return denied
    with _LOCK:
        path = state_path(state_root); state = _state(path)
        controller = state["controllers"].get(controller_id)
        if not isinstance(controller, dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        current = controller.get("lifecycle_state", "active")
        target = "active" if restore else "archived"
        if current == target:
            return HTTPStatus.OK, {"controller": _public_controller(controller), "idempotent": True,
                                   "webui_controller": _response_identity(state)}
        if not restore:
            active_runs = _active_run_ids(controller)
            if active_runs:
                return HTTPStatus.CONFLICT, _error("cannot archive controller with active runs", "ActiveRunsProtectiveBlock",
                                                   state, active_run_ids=active_runs)
        controller["lifecycle_state"] = target
        event = {"id": f"controller-lifecycle-{uuid.uuid4()}", "controller_id": controller_id,
                 "event_type": "restored" if restore else "archived", "occurred_at": _iso(),
                 "actor": operator.subject}
        controller.setdefault("lifecycle_history", []).append(copy.deepcopy(event))
        state.setdefault("controller_lifecycle_events", []).append(event)
        _audit(state, f"controller_{target}", actor=operator.subject, details=event)
        _write(path, state)
        return HTTPStatus.OK, {"controller": _public_controller(controller), "event": event,
                               "webui_controller": _response_identity(state)}


def _sync_freshness(record: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Project freshness independently from the edge connection observation."""
    now = now or _now()
    last = record.get("last_sync_at")
    age = None if not last else max(0.0, (now - _parse_time(last)).total_seconds())
    return {"state": "stale" if age is None or age > 24 * 60 * 60 else "fresh",
            "stale": age is None or age > 24 * 60 * 60, "age_seconds": age,
            "threshold_seconds": 24 * 60 * 60, "last_sync_at": last}


def _audit(state: dict[str, Any], event_type: str, *, actor: str | None = None,
           details: Mapping[str, Any] | None = None) -> dict[str, Any]:
    event = {"id": f"audit-{uuid.uuid4()}", "event_type": event_type,
             "occurred_at": _iso(), "actor": actor, "details": copy.deepcopy(dict(details or {}))}
    state.setdefault("audit_events", []).append(event)
    return event


def _operator_command(state: dict[str, Any], controller_id: str, command_kind: str,
                      *, operator: OperatorIdentity, run_id: str | None = None,
                      based_on_revision: int | None = None,
                      idempotency_key: str | None = None,
                      lease: Mapping[str, Any] | None = None,
                      fields: Mapping[str, Any] | None = None) -> dict[str, Any]:
    controller = state["controllers"][controller_id]
    if controller.get("lifecycle_state", "active") != "active":
        raise ValueError("controller is archived")
    generation = controller["binding"]["controller_generation"]
    commands = state.setdefault("commands", {}).setdefault(controller_id, [])
    if idempotency_key:
        prior = next((item for item in commands if item.get("idempotency_key") == idempotency_key), None)
        if isinstance(prior, dict):
            return copy.deepcopy(prior)
    next_cursor = max([int(item.get("delivery_cursor", 0)) for item in commands if isinstance(item, dict)] or [0]) + 1
    command = {"command_id": f"command-{uuid.uuid4()}", "controller_generation": generation,
               "command_kind": command_kind, "requested_at": _iso(), "requested_by": operator.subject,
               "auth_source": operator.source, "disposition": "queued", "delivery_eligible": True,
               "delivery_cursor": next_cursor}
    if run_id is not None: command["run_id"] = run_id
    if based_on_revision is not None: command["based_on_revision"] = based_on_revision
    if idempotency_key: command["idempotency_key"] = idempotency_key
    if lease is not None:
        command.update({"lease_id": lease["lease_id"], "lease_token": lease["lease_token"],
                        "lease_holder": lease["holder"], "lease_expires_at": lease["expires_at"]})
    if fields:
        command.update(copy.deepcopy(dict(fields)))
    commands.append(command)
    _COMMAND_CONDITION.notify_all()
    return copy.deepcopy(command)


def controller_freshness(*, controller_id: str | None = None,
                         state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    status, projection = controllers(controller_id=controller_id, state_root=state_root)
    if status is not HTTPStatus.OK:
        return status, projection
    if controller_id:
        projection["sync_freshness"] = _sync_freshness(projection["controller"])
    else:
        projection["sync_freshness"] = {item["id"]: _sync_freshness(item) for item in projection["controllers"]}
    return status, projection


def request_controller_refresh(controller_id: str, body: Any, *, operator: OperatorIdentity | None,
                               hardware: bool = False, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "manage_controller")
    if denied: return denied
    if not isinstance(body, dict): body = {}
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        if not isinstance(state["controllers"].get(controller_id), dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        if state["controllers"][controller_id].get("lifecycle_state", "active") != "active":
            return HTTPStatus.CONFLICT, _error("archived controller cannot receive refresh intent", "ControllerArchived", state)
        key = body.get("idempotency_key")
        if key is not None and (not isinstance(key, str) or not key.strip()):
            return HTTPStatus.BAD_REQUEST, _error("idempotency_key must be a non-empty string")
        kind = "hardware_rescan" if hardware else "central_refresh"
        command = _operator_command(state, controller_id, kind, operator=operator, idempotency_key=key)
        _audit(state, f"{kind}_requested", actor=operator.subject,
               details={"controller_id": controller_id, "command_id": command["command_id"]})
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"command": command, "intent": kind, "webui_controller": _response_identity(state)}


def _lease_status(lease: Mapping[str, Any]) -> str:
    if lease.get("revoked_at"): return "revoked"
    return "expired" if _parse_time(lease.get("expires_at")).timestamp() <= _now().timestamp() else "active"


def manual_control_lease(controller_id: str, body: Any, *, operator: OperatorIdentity | None,
                         action: str = "acquire", state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "operate_run")
    if denied: return denied
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        if not isinstance(state["controllers"].get(controller_id), dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        leases = state.setdefault("manual_control_leases", {})
        existing = leases.get(controller_id)
        if action == "get":
            return HTTPStatus.OK, {"controller_id": controller_id, "lease": copy.deepcopy(existing) if isinstance(existing, dict) else None,
                                   "lease_status": _lease_status(existing) if isinstance(existing, dict) else "none", "webui_controller": _response_identity(state)}
        if action in {"revoke", "emergency_release"}:
            if not isinstance(existing, dict): return HTTPStatus.NOT_FOUND, _error("manual control lease not found", "NotFound", state)
            if not existing.get("revoked_at"):
                safe_stop = None
                if action == "emergency_release":
                    safe_stop = _operator_command(
                        state, controller_id, "emergency_safe_stop", operator=operator,
                        idempotency_key=f"emergency-safe-stop:{existing['lease_id']}", lease=existing)
                existing["revoked_at"], existing["revoked_by"] = _iso(), operator.subject
                existing["status"] = "emergency_released" if action == "emergency_release" else "revoked"
                _fence_lease_commands(state.setdefault("commands", {}).setdefault(controller_id, []), existing)
                _audit(state, "manual_control_lease_emergency_release" if action == "emergency_release" else "manual_control_lease_revoked",
                       actor=operator.subject, details={"controller_id": controller_id, "lease_id": existing["lease_id"],
                                                        "safe_stop_command_id": safe_stop.get("command_id") if safe_stop else None})
            _write(path, state)
            response = {"lease": copy.deepcopy(existing), "idempotent": bool(existing.get("revoked_at")), "webui_controller": _response_identity(state)}
            if action == "emergency_release":
                response["safe_stop_intent"] = copy.deepcopy(safe_stop) if safe_stop else next(
                    (item for item in state.setdefault("commands", {}).setdefault(controller_id, [])
                     if item.get("idempotency_key") == f"emergency-safe-stop:{existing['lease_id']}"), None)
            return HTTPStatus.OK, response
        if action != "acquire": return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
        if isinstance(existing, dict) and _lease_status(existing) == "active" and existing.get("holder") != operator.subject:
            return HTTPStatus.CONFLICT, _error("manual control lease is held by another operator", "LeaseConflict", state)
        seconds = body.get("ttl_seconds", 15 * 60) if isinstance(body, dict) else 15 * 60
        if not isinstance(seconds, int) or not 0 < seconds <= 24 * 60 * 60:
            return HTTPStatus.BAD_REQUEST, _error("ttl_seconds must be between 1 and 86400")
        renewing = isinstance(existing, dict) and existing.get("holder") == operator.subject
        lease = {"lease_id": existing.get("lease_id") if renewing else f"lease-{uuid.uuid4()}",
                 "lease_token": existing.get("lease_token") if renewing else secrets.token_urlsafe(32),
                 "controller_id": controller_id, "holder": operator.subject, "acquired_at": _iso(),
                 "expires_at": _iso(_now() + timedelta(seconds=seconds)), "status": "active", "controller_generation": state["controllers"][controller_id]["binding"]["controller_generation"]}
        leases[controller_id] = lease
        if renewing:
            _operator_command(state, controller_id, "renew_manual_lease", operator=operator,
                              idempotency_key=f"manual-lease:{lease['lease_id']}:{lease['expires_at']}",
                              fields={"lease_id": lease["lease_id"], "lease_token": lease["lease_token"],
                                      "lease_holder": lease["holder"], "lease_expires_at": lease["expires_at"]})
        _audit(state, "manual_control_lease_acquired", actor=operator.subject,
               details={**lease, "lease_token": "[redacted]"})
        _write(path, state)
        return (HTTPStatus.OK if renewing else HTTPStatus.CREATED), {"lease": copy.deepcopy(lease), "idempotent": renewing,
                                                                       "webui_controller": _response_identity(state)}


def manual_control_command(controller_id: str, body: Any, *, operator: OperatorIdentity | None,
                           state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Queue a typed, fenced manual intent; delivery is not physical evidence."""
    denied = _require_operator(operator, "operate_run")
    if denied:
        return denied
    if not isinstance(body, dict) or body.get("operation") not in {"safe_stop", "stir_pulse", "heater_pulse", "pump_pulse"}:
        return HTTPStatus.BAD_REQUEST, _error("operation must be safe_stop, stir_pulse, heater_pulse, or pump_pulse", "InvalidManualOperation")
    idempotency_key = body.get("idempotency_key")
    if idempotency_key is not None and (not isinstance(idempotency_key, str) or not idempotency_key.strip()):
        return HTTPStatus.BAD_REQUEST, _error("idempotency_key must be a non-empty string")
    operation = body["operation"]
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        controller = state.get("controllers", {}).get(controller_id)
        if not isinstance(controller, dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        generation = controller.get("binding", {}).get("controller_generation")
        if not isinstance(generation, int):
            return HTTPStatus.CONFLICT, _error("controller generation is unavailable", "GenerationConflict", state)
        lease = state.setdefault("manual_control_leases", {}).get(controller_id)
        if operation != "safe_stop":
            if not isinstance(lease, dict) or _lease_status(lease) != "active" or lease.get("holder") != operator.subject:
                return HTTPStatus.CONFLICT, _error("an active lease held by this operator is required", "LeaseRequired", state)
            if lease.get("controller_generation") != generation:
                return HTTPStatus.CONFLICT, _error("manual lease generation is stale", "GenerationConflict", state)
        if operation == "pump_pulse":
            return HTTPStatus.CONFLICT, _error("physical pump commissioning is required; preview only", "PhysicalPumpDisabled", state)
        if operation == "heater_pulse":
            duration = body.get("duration_ms", 0); level = body.get("level", 0)
            if not isinstance(duration, int) or isinstance(duration, bool) or not 1 <= duration <= 250 or not isinstance(level, int) or isinstance(level, bool) or not 1 <= level <= 64:
                return HTTPStatus.BAD_REQUEST, _error("heater pulse level must be 1..64 and duration 1..250 ms", "InvalidHeaterPulse", state)
        if operation == "stir_pulse":
            duration = body.get("duration_ms", 0)
            channel = body.get("channel", 0)
            level = body.get("level", 1)
            if (not isinstance(duration, int) or isinstance(duration, bool) or not 1 <= duration <= 1000
                    or not isinstance(channel, int) or isinstance(channel, bool) or not 0 <= channel <= 1
                    or not isinstance(level, int) or isinstance(level, bool) or not 1 <= level <= 250):
                return HTTPStatus.BAD_REQUEST, _error("stir pulse channel must be 0..1, level 1..250, and duration 1..1000 ms", "InvalidStirPulse", state)
        ttl_seconds = body.get("ttl_seconds", 15)
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 60:
            return HTTPStatus.BAD_REQUEST, _error("ttl_seconds must be between 1 and 60", "InvalidCommandTTL", state)
        command_kind = "emergency_safe_stop" if operation == "safe_stop" else operation
        command = _operator_command(state, controller_id, command_kind, operator=operator,
                                     idempotency_key=idempotency_key, lease=lease if operation != "safe_stop" else None,
                                     fields={"instrument_id": body.get("instrument_id"), "target": body.get("target", {}),
                                             "operation": operation, "parameters": {key: body[key] for key in ("channel", "duration_ms", "level") if key in body},
                                             "expires_at": _iso(_now() + timedelta(seconds=ttl_seconds))})
        _audit(state, "manual_command_requested", actor=operator.subject,
               details={"controller_id": controller_id, "command_id": command["command_id"], "operation": operation})
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"command": copy.deepcopy(command), "webui_controller": _response_identity(state)}


def command_projection(controller_id: str, command_id: str | None = None, *,
                       state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Expose durable command state without implying physical execution."""
    with _LOCK:
        state = _state(state_path(state_root))
        if not isinstance(state.get("controllers", {}).get(controller_id), dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        commands = state.setdefault("commands", {}).setdefault(controller_id, [])
        _expire_commands(commands)
        _fence_lease_commands(commands, state.setdefault("manual_control_leases", {}).get(controller_id))
        if command_id is None:
            _write(state_path(state_root), state)
            return HTTPStatus.OK, {"controller_id": controller_id, "commands": copy.deepcopy(commands),
                                   "webui_controller": _response_identity(state)}
        command = next((item for item in commands if isinstance(item, dict) and item.get("command_id") == command_id), None)
        if not isinstance(command, dict):
            return HTTPStatus.NOT_FOUND, _error("command not found", "NotFound", state)
        _write(state_path(state_root), state)
        return HTTPStatus.OK, {"controller_id": controller_id, "command": copy.deepcopy(command),
                               "webui_controller": _response_identity(state)}


def release_history(*, controller_id: str | None = None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    with _LOCK:
        state = _state(state_path(state_root))
        deployments = [item for item in state.get("release_deployments", []) if isinstance(item, dict) and (controller_id is None or item.get("controller_id") == controller_id)]
        deployment_ids = {item.get("deployment_id") for item in deployments}
        events = [item for item in state.get("release_events", []) if isinstance(item, dict) and (not deployment_ids or item.get("deployment_id") in deployment_ids)]
        return HTTPStatus.OK, {"releases": copy.deepcopy(state.get("release_history", [])), "deployments": copy.deepcopy(deployments),
                               "events": copy.deepcopy(events), "rollback_requests": copy.deepcopy(state.get("rollback_requests", [])),
                               "webui_controller": _response_identity(state)}


def audit_events(*, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    with _LOCK:
        state = _state(state_path(state_root))
        return HTTPStatus.OK, {"audit_events": copy.deepcopy(state.get("audit_events", [])),
                               "webui_controller": _response_identity(state)}


def edge_facts(*, controller_id: str | None = None, run_id: str | None = None,
               kind: str = "all", limit: int = 500,
               state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Return bounded projections of facts reported by edge controllers.

    These are not command or run-intent projections. ACKs and observations
    retain their edge source and never imply physical application of intent.
    """
    kinds = {"all", "telemetry", "measurements", "activities", "events", "evidence", "logs"}
    if kind not in kinds:
        return HTTPStatus.BAD_REQUEST, _error("unsupported edge fact kind")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 5000:
        return HTTPStatus.BAD_REQUEST, _error("limit must be an integer between 1 and 5000")
    with _LOCK:
        state = _state(state_path(state_root))
        controllers = state.get("controllers", {})
        if controller_id is not None and not isinstance(controllers.get(controller_id), dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        telemetry: list[dict[str, Any]] = []
        measurements: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []
        acknowledgements: list[dict[str, Any]] = []
        diagnostic_evidence: list[dict[str, Any]] = []
        for current_id, controller in controllers.items():
            if controller_id is not None and current_id != controller_id:
                continue
            if not isinstance(controller, dict):
                continue
            raw_telemetry = [copy.deepcopy(item) for item in controller.get("telemetry", []) if isinstance(item, dict)]
            raw_events = [copy.deepcopy(item) for item in controller.get("events", []) if isinstance(item, dict)]
            raw_acks = [copy.deepcopy(item) for item in controller.get("acknowledgements", []) if isinstance(item, dict)]
            if run_id is not None:
                raw_telemetry = [item for item in raw_telemetry if item.get("run_id") == run_id or str(item.get("stream_id", "")).startswith(f"{run_id}:")]
                raw_events = [item for item in raw_events if item.get("run_id") == run_id]
            for item in (*raw_telemetry, *raw_events, *raw_acks):
                item.setdefault("controller_id", current_id)
            telemetry.extend(raw_telemetry)
            measurements.extend(_normalized_telemetry(str(current_id), raw_telemetry))
            events.extend(raw_events)
            acknowledgements.extend(raw_acks)
            observation = controller.get("hardware_observation")
            if isinstance(observation, dict) and run_id is None:
                diagnostic_evidence.append({**copy.deepcopy(observation), "controller_id": current_id})
        activities = copy.deepcopy(events)
        logs = copy.deepcopy(events)
        for rows in (telemetry, measurements, activities, events, acknowledgements, diagnostic_evidence, logs):
            del rows[:-limit]
        payload: dict[str, Any] = {"controller_id": controller_id, "run_id": run_id,
                                   "source": "edge_facts", "webui_controller": _response_identity(state)}
        if kind in {"all", "telemetry"}: payload["telemetry"] = telemetry
        if kind in {"all", "measurements"}: payload["measurements"] = measurements
        if kind in {"all", "activities"}: payload["activities"] = activities
        if kind in {"all", "events"}: payload["events"] = events
        if kind in {"all", "evidence"}: payload["evidence"] = diagnostic_evidence + acknowledgements
        if kind in {"all", "logs"}: payload["logs"] = logs
        return HTTPStatus.OK, payload


def request_rollback(controller_id: str, body: Any, *, operator: OperatorIdentity | None,
                     state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "update_controller")
    if denied: return denied
    if not isinstance(body, dict) or not isinstance(body.get("release_id"), str):
        return HTTPStatus.BAD_REQUEST, _error("release_id is required")
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        controller = state.get("controllers", {}).get(controller_id)
        if not isinstance(controller, dict): return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        generation = controller.get("binding", {}).get("controller_generation")
        if not isinstance(generation, int) or generation <= 0: return HTTPStatus.CONFLICT, _error("controller generation is unavailable", "GenerationConflict", state)
        target = body["release_id"]
        releases = [item for item in state.get("release_history", []) if isinstance(item, dict)]
        deployments = [item for item in state.get("release_deployments", []) if isinstance(item, dict)]
        events = [item for item in state.get("release_events", []) if isinstance(item, dict)]
        observed = rollback_eligibility(
            "__current_release_unknown__", releases, deployments, events,
            controller_id=controller_id, controller_generation=generation,
        )
        if not any(item.get("release_id") == target for item in releases):
            return HTTPStatus.CONFLICT, _error("rollback release is not registered", "RollbackReleaseNotFound", state)
        if not any(item.get("release_id") == target for item in observed["candidates"]):
            return HTTPStatus.CONFLICT, _error("rollback release has no observed eligible deployment", "RollbackNotEligible", state)
        key = body.get("idempotency_key")
        if key is not None:
            prior = next((item for item in state["rollback_requests"] if item.get("idempotency_key") == key), None)
            if isinstance(prior, dict): return HTTPStatus.OK, {"rollback_request": copy.deepcopy(prior), "idempotent": True, "webui_controller": _response_identity(state)}
        request = {"request_id": f"rollback-{uuid.uuid4()}", "release_id": body["release_id"], "controller_id": controller_id,
                   "controller_generation": generation, "requested_by": operator.subject, "auth_source": operator.source,
                   "requested_at": _iso(), "reason": body.get("reason", "operator requested rollback"), "status": "requested"}
        if isinstance(key, str): request["idempotency_key"] = key
        state["rollback_requests"].append(request)
        _audit(state, "rollback_requested", actor=operator.subject, details=request)
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"rollback_request": copy.deepcopy(request), "webui_controller": _response_identity(state)}


def _manifest_for_controller(state: dict[str, Any], controller_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    controller = state["controllers"].get(controller_id)
    if not isinstance(controller, dict):
        return None, None
    manifest = controller.get("recovery_manifest")
    return controller, copy.deepcopy(manifest) if isinstance(manifest, dict) else None


def _snapshot_versions(state: dict[str, Any], stable_id: str) -> dict[str, Any]:
    value = state["content_snapshots"].get(stable_id)
    if not isinstance(value, dict):
        return {}
    # Accept the simple record shape from early development state too.
    if isinstance(value.get("id"), str):
        revision = value.get("revision")
        return {str(revision): value} if revision is not None else {}
    return value


def _recovery_snapshot(manifest: dict[str, Any], snapshot_id: str) -> dict[str, Any] | None:
    snapshots = manifest.get("source_metadata")
    if not isinstance(snapshots, list):
        return None
    return next((copy.deepcopy(item) for item in snapshots if isinstance(item, dict) and item.get("id") == snapshot_id), None)


def recovery_diff(controller_id: str, *, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Compare edge ContentSnapshots without timestamp-based resolution."""
    with _LOCK:
        state = _state(state_path(state_root))
        _, manifest = _manifest_for_controller(state, controller_id)
        if manifest is None:
            return HTTPStatus.NOT_FOUND, _error("full recovery manifest not available", "RecoveryManifestNotFound", state)
        rows: list[dict[str, Any]] = []
        for edge in manifest.get("source_metadata", []):
            if not isinstance(edge, dict) or not isinstance(edge.get("id"), str):
                continue
            versions = _snapshot_versions(state, edge["id"])
            edge_revision = edge.get("revision")
            central = versions.get(str(edge_revision)) if edge_revision is not None else None
            if not versions:
                status = "missing_central"
            elif isinstance(central, dict) and central.get("digest") == edge.get("digest"):
                status = "identical"
            else:
                status = "conflict"
                # The comparison remains stable-id first; expose a central
                # version for review even when revisions differ.
                central = central or next(iter(versions.values()))
            rows.append({"object_type": "ContentSnapshot", "object_id": edge["id"],
                         "edge_revision": edge_revision, "edge_digest": edge.get("digest"),
                         "central_revision": central.get("revision") if isinstance(central, dict) else None,
                         "central_digest": central.get("digest") if isinstance(central, dict) else None,
                         "state": status})
        return HTTPStatus.OK, {"controller_id": controller_id, "manifest_id": manifest.get("id"),
                               "items": rows, "webui_controller": _response_identity(state)}


def import_recovery_snapshot(controller_id: str, body: Any, *, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Apply an explicitly selected, non-destructive recovery disposition."""
    if not isinstance(body, dict) or not isinstance(body.get("snapshot_id"), str) or body.get("action") not in {"import", "historical", "fork", "keep_central", "ignore"}:
        return HTTPStatus.BAD_REQUEST, _error("snapshot_id and recovery action are required")
    with _LOCK:
        path = state_path(state_root)
        state = _state(path)
        _, manifest = _manifest_for_controller(state, controller_id)
        if manifest is None:
            return HTTPStatus.NOT_FOUND, _error("full recovery manifest not available", "RecoveryManifestNotFound", state)
        snapshot = _recovery_snapshot(manifest, body["snapshot_id"])
        if snapshot is None or not isinstance(snapshot.get("revision"), (str, int)) or not isinstance(snapshot.get("digest"), str):
            return HTTPStatus.NOT_FOUND, _error("recovered ContentSnapshot not found or incomplete", "RecoverySnapshotNotFound", state)
        stable_id, revision, action = snapshot["id"], str(snapshot["revision"]), body["action"]
        versions = _snapshot_versions(state, stable_id)
        exact = versions.get(revision)
        result: dict[str, Any] = {"controller_id": controller_id, "snapshot_id": stable_id, "action": action, "at": _iso()}
        if action == "import":
            if versions:
                return HTTPStatus.CONFLICT, _error("central snapshot already exists; choose historical, fork, keep_central, or ignore", "RecoveryConflict", state)
            state["content_snapshots"][stable_id] = {revision: copy.deepcopy(snapshot)}
            result["outcome"] = "imported"
        elif action == "historical":
            if exact is not None:
                return HTTPStatus.CONFLICT, _error("central already has this revision; historical import cannot overwrite it", "RecoveryConflict", state)
            state["content_snapshots"].setdefault(stable_id, {})[revision] = copy.deepcopy(snapshot)
            result["outcome"] = "historical_imported"
        elif action == "fork":
            fork_id = f"recovered-{stable_id}-{uuid.uuid4()}"
            fork = copy.deepcopy(snapshot); fork["id"] = fork_id; fork["recovered_from"] = {"id": stable_id, "revision": snapshot["revision"], "digest": snapshot["digest"]}
            state["content_snapshots"][fork_id] = {revision: fork}
            result.update({"outcome": "forked", "fork_id": fork_id})
        else:
            result["outcome"] = action
        state["recovery_imports"].append(result)
        _write(path, state)
        return HTTPStatus.OK, {**result, "webui_controller": _response_identity(state)}


def request_recovery_manifest(controller_id: str, *, requested_by: str = "webui_operator",
                              auth_source: str | None = None,
                              state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Queue a bounded, explicit request; routine sync remains compact."""
    with _LOCK:
        path = state_path(state_root); state = _state(path)
        controller = state["controllers"].get(controller_id)
        if not isinstance(controller, dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        command = {"command_id": f"command-{uuid.uuid4()}", "controller_generation": controller["binding"]["controller_generation"],
                   "command_kind": "request_recovery_manifest", "requested_at": _iso(), "requested_by": requested_by,
                   "auth_source": auth_source, "disposition": "queued"}
        state["commands"].setdefault(controller_id, []).append(command)
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"command": copy.deepcopy(command), "webui_controller": _response_identity(state)}


def runs(*, run_id: str | None = None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Public, compact run projections reconstructed from edge summaries.

    The edge remains authoritative.  This deliberately exposes no controller
    credential or raw telemetry/event history; those need bounded window APIs.
    """
    with _LOCK:
        state = _state(state_path(state_root))
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RUN_PROJECTION:
            return HTTPStatus.BAD_REQUEST, _error(f"limit must be an integer between 1 and {MAX_RUN_PROJECTION}")
        if controller_id is not None and not isinstance(state["controllers"].get(controller_id), dict):
            return HTTPStatus.NOT_FOUND, _error("controller not found", "NotFound", state)
        projected: list[dict[str, Any]] = []
        for current_controller_id, controller in state["controllers"].items():
            if controller_id is not None and current_controller_id != controller_id:
                continue
            if not isinstance(controller, dict):
                continue
            summary = controller.get("recovery_summary") or controller.get("recovery_manifest") or {}
            for run in summary.get("runs", []) if isinstance(summary, dict) else []:
                if isinstance(run, dict):
                    public = _public_run(run)
                    public["controller_id"] = current_controller_id
                    public["connection_state"] = controller.get("connection_state")
                    if state_filter is not None and public.get("state") != state_filter:
                        continue
                    projected.append(public)
        projected = projected[-limit:]
        if run_id is not None:
            found = next((run for run in projected if run.get("id") == run_id), None)
            if found is not None:
                owner = next((controller for controller in state["controllers"].values() if isinstance(controller, dict) and controller.get("id") == found.get("controller_id")), None)
                if isinstance(owner, dict):
                    found["events"] = [_public_run(item) for item in owner.get("events", []) if isinstance(item, dict) and item.get("run_id") == run_id][-limit:]
                    found["telemetry"] = [_public_run(item) for item in owner.get("telemetry", []) if isinstance(item, dict) and (item.get("run_id") == run_id or str(item.get("stream_id", "")).startswith(f"{run_id}:"))][-limit:]
                    found["execution_evidence"] = {"source": "edge_summary", "steps": found.get("steps", found.get("completed_steps")), "legacy_runner": not bool(found.get("steps") or found.get("completed_steps"))}
            return (HTTPStatus.OK, {"run": found, "webui_controller": _response_identity(state)}) if found else (HTTPStatus.NOT_FOUND, _error("run not found", "NotFound", state))
        return HTTPStatus.OK, {"runs": projected, "webui_controller": _response_identity(state)}


def mutate_run(run_id: str, body: Any, *, requested_by: str = "webui_operator",
               auth_source: str | None = None,
               state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Queue a revision-fenced run lifecycle command; delivery is not execution."""
    if not isinstance(body, dict) or body.get("action") not in {"pause", "resume", "stop", "maintenance_mode"} or not isinstance(body.get("expected_revision"), int):
        return HTTPStatus.BAD_REQUEST, _error("action (pause, resume, stop, or maintenance_mode) and integer expected_revision are required")
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        selected: tuple[str, dict[str, Any]] | None = None
        for controller_id, controller in state["controllers"].items():
            summary = controller.get("recovery_summary") or controller.get("recovery_manifest") or {}
            for run in summary.get("runs", []) if isinstance(summary, dict) else []:
                if isinstance(run, dict) and run.get("id") == run_id:
                    selected = (controller_id, run); break
            if selected: break
        if selected is None:
            return HTTPStatus.NOT_FOUND, _error("run not found", "NotFound", state)
        controller_id, run = selected
        current_revision = run.get("current_revision")
        if current_revision != body["expected_revision"]:
            return HTTPStatus.CONFLICT, {"kind": "StaleRunRevision", "error": "run revision is stale", "run": copy.deepcopy(run), "current_revision": current_revision}
        controller = state["controllers"][controller_id]
        command = {"command_id": f"command-{uuid.uuid4()}", "controller_generation": controller["binding"]["controller_generation"],
                   "command_kind": f"{body['action']}_run", "run_id": run_id, "based_on_revision": current_revision,
                   "requested_at": _iso(), "requested_by": requested_by, "auth_source": auth_source,
                   "disposition": "queued"}
        state["commands"].setdefault(controller_id, []).append(command)
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"command": copy.deepcopy(command), "webui_controller": _response_identity(state)}


def _run_revision(state: dict[str, Any], run_id: str) -> tuple[str, dict[str, Any]] | None:
    from .evolver_run_resources import _run
    return _run(state, run_id)


def run_resources(run_id: str, *, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    with _LOCK:
        state = _state(state_path(state_root))
        if _run_revision(state, run_id) is None:
            return HTTPStatus.NOT_FOUND, _error("run not found", "NotFound", state)
        assignments = [copy.deepcopy(item) for item in state["run_resource_assignments"] if isinstance(item, dict) and item.get("run_id") == run_id]
        active = [item for item in assignments if item.get("assignment_state") == "assigned"]
        capabilities = sorted({capability for item in active for capability in item.get("required_capabilities", []) if isinstance(capability, str)})
        targets = [item.get("target_temperature") for item in active if isinstance(item.get("target_temperature"), (int, float))]
        return HTTPStatus.OK, {"run_id": run_id, "assignments": assignments,
                              "readiness": run_resource_readiness(state, run_id, target_temperature=targets[-1] if targets else None, required_capabilities=capabilities),
                              "events": [copy.deepcopy(item) for item in state["run_resource_events"] if isinstance(item, dict) and item.get("run_id") == run_id],
                              "webui_controller": _response_identity(state)}


def mutate_run_resource(run_id: str, body: Any, *, operator: OperatorIdentity | None,
                        assignment_id: str | None = None, action: str = "add",
                        state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    denied = _require_operator(operator, "operate_run")
    if denied:
        return denied
    if not isinstance(body, dict):
        return HTTPStatus.BAD_REQUEST, _error("body must be an object")
    with _LOCK:
        path, state = state_path(state_root), _state(state_path(state_root))
        located = _run_revision(state, run_id)
        if located is None:
            return HTTPStatus.NOT_FOUND, _error("run not found", "NotFound", state)
        controller_id, run = located
        expected = body.get("expected_revision")
        if not isinstance(expected, int) or run.get("current_revision") != expected:
            return HTTPStatus.CONFLICT, _error("run revision is stale", "StaleRunRevision", state,
                                               current_revision=run.get("current_revision"))
        try:
            if action == "add":
                item = add_run_resource(state, run_id, body, actor=operator.subject)
            elif action == "release" and assignment_id:
                item = transition_run_resource(state, run_id, assignment_id, "release", actor=operator.subject, reason=body.get("reason"))
            elif action == "confirm_move" and assignment_id:
                item = next((copy.deepcopy(row) for row in reversed(state.get("run_resource_assignments", []))
                             if isinstance(row, dict) and row.get("run_id") == run_id and row.get("id") == assignment_id
                             and row.get("assignment_state") == "assigned"), None)
                if item is None:
                    raise KeyError("active assignment not found")
                state.setdefault("run_resource_events", []).append({"id": f"run-resource-event-{uuid.uuid4()}", "event_type": "move_confirmed", "run_id": run_id, "assignment_id": assignment_id, "occurred_at": body.get("moved_at") or _iso(), "actor": operator.subject, "note": body.get("note")})
            elif action == "replace" and assignment_id:
                already_replaced = any(isinstance(row, dict) and row.get("supersedes_id") == assignment_id
                                       and row.get("assignment_state") == "assigned"
                                       for row in state.get("run_resource_assignments", []))
                terminal = next((row for row in state.get("run_resource_assignments", [])
                                 if isinstance(row, dict)
                                 and (row.get("id") == assignment_id or row.get("supersedes_id") == assignment_id)
                                 and row.get("assignment_state") in {"released", "replaced"}), None)
                if already_replaced:
                    item = next(row for row in state["run_resource_assignments"]
                                if isinstance(row, dict) and row.get("supersedes_id") == assignment_id
                                and row.get("assignment_state") == "assigned")
                elif terminal is not None:
                    replacement_body = dict(body)
                    replacement_body["replaces_assignment_id"] = terminal["id"]
                    item = add_run_resource(state, run_id, replacement_body, actor=operator.subject)
                else:
                    transition_run_resource(state, run_id, assignment_id, "replace", actor=operator.subject, reason=body.get("reason") or "replaced")
                    replacement_body = dict(body)
                    replacement_body["replaces_assignment_id"] = assignment_id
                    item = add_run_resource(state, run_id, replacement_body, actor=operator.subject)
            else:
                return HTTPStatus.BAD_REQUEST, _error("unsupported resource action")
        except KeyError as exc:
            return HTTPStatus.NOT_FOUND, _error(str(exc), "NotFound", state)
        except ValueError as exc:
            return HTTPStatus.CONFLICT, _error(str(exc), "ResourceLifecycleConflict", state)
        # Resource changes are central intent and therefore queue a fenced edge
        # command; the assignment fact is durable even when delivery is offline.
        controller = state["controllers"][controller_id]
        command = {"command_id": f"command-{uuid.uuid4()}", "controller_generation": controller["binding"]["controller_generation"],
                   "command_kind": f"{action}_run_resource", "run_id": run_id, "resource_assignment_id": item["id"],
                   "based_on_revision": expected, "requested_at": _iso(), "requested_by": operator.subject,
                   "auth_source": operator.source, "disposition": "queued"}
        state["commands"].setdefault(controller_id, []).append(command)
        _write(path, state)
        return HTTPStatus.ACCEPTED, {"assignment": item, "command": copy.deepcopy(command), "webui_controller": _response_identity(state)}


def dispatch(method: str, path: str, body: Any, *, query: str = "", authorization: str | None = None,
             operator: OperatorIdentity | None = None, state_root: Path | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    if path == "/api/evolver/experiments/validate":
        if method != "POST" or not isinstance(body, dict) or not isinstance(body.get("definition"), dict):
            return HTTPStatus.BAD_REQUEST, _error("definition must be a JSON object")
        from .experiment_actions import validate_experiment
        return HTTPStatus.OK, validate_experiment(
            body["definition"], body.get("selected_calibration_artifacts", []),
            resolved_at=str(body.get("resolved_at", _iso())),
        )
    if path == "/api/evolver/experiments/describe":
        if method != "POST" or not isinstance(body, dict) or not isinstance(body.get("definition"), dict):
            return HTTPStatus.BAD_REQUEST, _error("definition must be a JSON object")
        from .experiment_actions import describe_experiment
        return HTTPStatus.OK, describe_experiment(body["definition"])
    if path == "/api/evolver/experiments/plan":
        if method != "POST" or not isinstance(body, dict) or not isinstance(body.get("bundle"), dict):
            return HTTPStatus.BAD_REQUEST, _error("bundle must be a JSON object")
        from .experiment_actions import plan_experiment
        return HTTPStatus.OK, plan_experiment(
            body["bundle"], state=body.get("state"), run_id=body.get("run_id"),
            target_temperature=body.get("target_temperature"),
            required_capabilities=body.get("required_capabilities"),
        )
    if path == "/api/evolver/audit-events":
        return audit_events(state_root=state_root) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/releases/history" or (path.startswith("/api/evolver/controllers/") and path.endswith("/release-history")):
        controller_id = path.removeprefix("/api/evolver/controllers/").removesuffix("/release-history").strip("/") or None
        return release_history(controller_id=controller_id, state_root=state_root) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path.startswith("/api/evolver/controllers/") and path.endswith("/rollback"):
        controller_id = path.removeprefix("/api/evolver/controllers/").removesuffix("/rollback").strip("/")
        return request_rollback(controller_id, body, operator=operator, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/controllers/freshness":
        return controller_freshness(state_root=state_root) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/server-endpoints":
        return server_endpoints() if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/releases/catalog":
        return configured_release_catalog(state_root=state_root) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/releases/build":
        if method != "POST":
            return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
        from .server_release_actions import release_build
        return release_build(body if isinstance(body, dict) else {}, operator=operator)
    if path == "/api/evolver/dashboard":
        from urllib.parse import parse_qs
        range_name = parse_qs(query).get("range", ["1h"])[0]
        return dashboard(range_name=range_name) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/calibration-workspace":
        return calibration_workspace(state_root=state_root) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path in {"/api/evolver/od-blanks", "/api/evolver/calibrations/od-blanks"}:
        if method != "GET":
            return HTTPStatus.METHOD_NOT_ALLOWED, _error("OD blank evidence is read-only", "MethodNotAllowed")
        from urllib.parse import parse_qs
        instrument_id = parse_qs(query).get("instrument_id", [None])[0]
        raw_channel = parse_qs(query).get("channel_index", [None])[0]
        try:
            channel_index = int(raw_channel) if raw_channel is not None else None
        except ValueError:
            return HTTPStatus.BAD_REQUEST, _error("channel_index must be an integer")
        return od_blank_evidence(instrument_id=instrument_id, channel_index=channel_index, state_root=state_root)
    if path == "/api/evolver/calibrations":
        return calibrations(state_root=state_root) if method == "GET" else create_calibration_session(body, operator=operator, state_root=state_root)
    if path == "/api/evolver/calibrations/pump-fixtures" and method == "POST":
        if not isinstance(body, dict) or not isinstance(body.get("instrument_id"), str):
            return HTTPStatus.BAD_REQUEST, _error("instrument_id is required")
        return create_pump_fixture_artifacts(body["instrument_id"], body.get("records"), operator=operator, state_root=state_root)
    if path.startswith("/api/evolver/calibrations/"):
        suffix = path.removeprefix("/api/evolver/calibrations/").strip("/")
        if "/" not in suffix and method == "GET": return calibrations(calibration_id=suffix, state_root=state_root)
        if suffix.startswith("artifacts/") and suffix.endswith("/invalidate") and method == "POST":
            artifact_id = suffix.removeprefix("artifacts/").removesuffix("/invalidate")
            reason = body.get("reason", "operator invalidation") if isinstance(body, dict) else "operator invalidation"
            return invalidate_calibration_artifact(artifact_id, reason=reason, operator=operator, state_root=state_root)
        if suffix.startswith("artifacts/") and suffix.endswith("/deliver") and method == "POST":
            request_id = body.get("request_id") if isinstance(body, dict) else None
            if request_id is not None and not isinstance(request_id, str):
                return HTTPStatus.BAD_REQUEST, _error("request_id must be a string")
            return deliver_calibration_artifact(suffix.removeprefix("artifacts/").removesuffix("/deliver"), request_id=request_id, operator=operator, state_root=state_root)
        if suffix.startswith("artifacts/") and suffix.endswith("/supersede") and method == "POST":
            if not isinstance(body, dict) or not isinstance(body.get("superseding_artifact_id"), str):
                return HTTPStatus.BAD_REQUEST, _error("superseding_artifact_id is required")
            return supersede_calibration_artifact(suffix.removeprefix("artifacts/").removesuffix("/supersede"), superseding_artifact_id=body["superseding_artifact_id"], operator=operator, state_root=state_root)
        if suffix == "sessions" and method == "POST":
            return create_calibration_session(body, operator=operator, state_root=state_root)
        if suffix.startswith("sessions/"):
            session_id, _, action = suffix.removeprefix("sessions/").partition("/")
            if action == "capture" and method == "POST": return capture_latest_observation(session_id, body, operator=operator, state_root=state_root)
            if action in {"observations", "fit", "accept", "cancel"} and method == "POST":
                return calibration_session_mutation(session_id, {"observations": "observation"}.get(action, action), body, operator=operator, state_root=state_root)
        return calibrations(calibration_id=suffix, state_root=state_root) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path.startswith("/api/evolver/interventions/") and path.endswith("/complete"):
        intervention_id = path.removeprefix("/api/evolver/interventions/").removesuffix("/complete").strip("/")
        return complete_intervention(intervention_id, body, operator=operator) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/instruments":
        return instruments() if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/maintenance":
        return maintenance() if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path.startswith("/api/evolver/instruments/"):
        if path.endswith("/name"):
            instrument_id = path.removeprefix("/api/evolver/instruments/").removesuffix("/name").strip("/")
            return rename_entity("instruments", instrument_id, body.get("name") if isinstance(body, dict) else None, operator=operator) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        return instruments(instrument_id=path.rsplit("/", 1)[-1]) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/runs":
        return runs() if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/controllers":
        return controllers() if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/enrollment-tokens":
        if method != "POST":
            return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
        denied = _require_operator(operator, "manage_controller")
        if denied:
            return denied
        body = body if isinstance(body, dict) else {}
        return create_enrollment_token(server_url=body.get("server_url", ""), ttl_seconds=body.get("ttl_seconds", DEFAULT_TOKEN_TTL_SECONDS),
                                       purpose=body.get("purpose", "enrollment"), release_binding=body.get("release_binding"))
    if path == "/api/evolver/controllers/enroll":
        return enroll(body, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/controllers/handoff/release":
        credential = authorization.removeprefix("Bearer ") if isinstance(authorization, str) and authorization.startswith("Bearer ") else None
        return release_handoff(body, credential=credential, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/controllers/commands/wait":
        credential = authorization.removeprefix("Bearer ") if isinstance(authorization, str) and authorization.startswith("Bearer ") else None
        controller_id = body.get("controller_id") if isinstance(body, dict) else None
        if not isinstance(controller_id, str) or not controller_id:
            return HTTPStatus.BAD_REQUEST, _error("controller_id is required")
        return wait_for_command(controller_id, body, credential=credential, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path == "/api/evolver/controllers/sync":
        credential = authorization.removeprefix("Bearer ") if isinstance(authorization, str) and authorization.startswith("Bearer ") else None
        return sync(body, credential=credential, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path.startswith("/api/evolver/controllers/"):
        suffix = path.removeprefix("/api/evolver/controllers/")
        if "/commands" in suffix and method == "GET":
            controller_id, marker, command_id = suffix.partition("/commands/")
            if marker and command_id:
                return command_projection(controller_id, command_id, state_root=state_root)
            if suffix.endswith("/commands"):
                return command_projection(suffix.removesuffix("/commands"), state_root=state_root)
        if suffix.endswith("/endpoint"):
            controller_id = suffix.removesuffix("/endpoint").strip("/")
            return assign_controller_endpoint(controller_id, body, operator=operator, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/sync-freshness"):
            controller_id = suffix.removesuffix("/sync-freshness").strip("/")
            return controller_freshness(controller_id=controller_id, state_root=state_root) if method == "GET" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/refresh") or suffix.endswith("/hardware-rescan"):
            hardware = suffix.endswith("/hardware-rescan")
            controller_id = suffix.removesuffix("/hardware-rescan" if hardware else "/refresh").strip("/")
            return request_controller_refresh(controller_id, body, operator=operator, hardware=hardware, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/desired-release"):
            controller_id = suffix.removesuffix("/desired-release").strip("/")
            return set_desired_release(controller_id, body, operator=operator, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/archive") or suffix.endswith("/restore"):
            restore = suffix.endswith("/restore")
            marker = "/restore" if restore else "/archive"
            controller_id = suffix.removesuffix(marker).strip("/")
            return archive_controller(controller_id, operator=operator, state_root=state_root, restore=restore) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/manual-control-lease"):
            controller_id = suffix.removesuffix("/manual-control-lease").strip("/")
            if method == "GET":
                action = "get"
            elif method == "POST":
                action = "acquire"
            else:
                return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
            return manual_control_lease(controller_id, body, operator=operator, action=action, state_root=state_root)
        if suffix.endswith("/manual-control-lease/revoke") or suffix.endswith("/manual-control-lease/emergency-release"):
            emergency = suffix.endswith("/emergency-release")
            marker = "/manual-control-lease/emergency-release" if emergency else "/manual-control-lease/revoke"
            controller_id = suffix.removesuffix(marker).strip("/")
            return manual_control_lease(controller_id, body, operator=operator, action="emergency_release" if emergency else "revoke", state_root=state_root) if method in {"POST", "DELETE"} else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/manual-command"):
            controller_id = suffix.removesuffix("/manual-command").strip("/")
            return manual_control_command(controller_id, body, operator=operator, state_root=state_root) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        for fact_kind in ("measurements", "telemetry", "activities", "events", "evidence", "logs"):
            if suffix.endswith(f"/{fact_kind}"):
                controller_id = suffix.removesuffix(f"/{fact_kind}").strip("/")
                if method != "GET":
                    return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
                from urllib.parse import parse_qs
                params = parse_qs(query)
                try:
                    limit = int(params.get("limit", ["500"])[0])
                except ValueError:
                    return HTTPStatus.BAD_REQUEST, _error("limit must be an integer")
                return edge_facts(controller_id=controller_id, run_id=params.get("run_id", [None])[0],
                                  kind=fact_kind, limit=limit, state_root=state_root)
        if suffix.endswith("/name"):
            controller_id = suffix.removesuffix("/name").strip("/")
            return rename_entity("controllers", controller_id, body.get("name") if isinstance(body, dict) else None, operator=operator) if method == "POST" else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/recovery/diff"):
            controller_id = suffix.removesuffix("/recovery/diff").rstrip("/")
            return recovery_diff(controller_id) if method == "GET" and controller_id else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/recovery/imports"):
            controller_id = suffix.removesuffix("/recovery/imports").rstrip("/")
            denied = _require_operator(operator, "recover_controller")
            if denied:
                return denied
            return import_recovery_snapshot(controller_id, body) if method == "POST" and controller_id else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
        if suffix.endswith("/recovery"):
            controller_id = suffix.removesuffix("/recovery").rstrip("/")
            if method == "POST" and controller_id:
                denied = _require_operator(operator, "recover_controller")
                if denied:
                    return denied
                return request_recovery_manifest(controller_id, requested_by=operator.subject, auth_source=operator.source)
            if method == "GET" and controller_id:
                with _LOCK:
                    state = _state(state_path())
                    _, manifest = _manifest_for_controller(state, controller_id)
                    return (HTTPStatus.OK, {"controller_id": controller_id, "recovery_manifest": manifest,
                                            "webui_controller": _response_identity(state)}) if manifest is not None else (HTTPStatus.NOT_FOUND, _error("full recovery manifest not available", "RecoveryManifestNotFound", state))
            return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
        controller_id = suffix
        return controllers(controller_id=controller_id) if method == "GET" and controller_id else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    if path.startswith("/api/evolver/runs/"):
        suffix = path.removeprefix("/api/evolver/runs/")
        if "/resources" in suffix:
            run_id, _, resource_suffix = suffix.partition("/resources")
            if method == "GET" and not resource_suffix:
                return run_resources(run_id, state_root=state_root)
            if method == "POST" and not resource_suffix:
                return mutate_run_resource(run_id, body, operator=operator, state_root=state_root)
            if method == "POST" and resource_suffix.startswith("/"):
                assignment_id, _, operation = resource_suffix.removeprefix("/").partition("/")
                if operation == "release":
                    return mutate_run_resource(run_id, body, operator=operator, assignment_id=assignment_id, action="release", state_root=state_root)
                if operation == "replace":
                    return mutate_run_resource(run_id, body, operator=operator, assignment_id=assignment_id, action="replace", state_root=state_root)
                if operation == "confirm-move":
                    return mutate_run_resource(run_id, body, operator=operator, assignment_id=assignment_id, action="confirm_move", state_root=state_root)
            return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
        if suffix.endswith("/commands"):
            if method != "POST":
                return HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed")
            denied = _require_operator(operator, "operate_run")
            if denied:
                return denied
            return mutate_run(suffix.removesuffix("/commands").rstrip("/"), body,
                              requested_by=operator.subject, auth_source=operator.source)
        return runs(run_id=suffix) if method == "GET" and suffix else (HTTPStatus.METHOD_NOT_ALLOWED, _error("method not allowed", "MethodNotAllowed"))
    return HTTPStatus.NOT_FOUND, _error("not found", "NotFound")
