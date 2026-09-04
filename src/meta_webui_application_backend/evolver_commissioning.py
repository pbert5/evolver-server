"""eVOLVER commissioning and calibration policy primitives.

These functions describe evidence and policy only. They never turn an ACK into
physical success and never interrupt an active run because calibration aged.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

COMMISSIONING_STATES = ("detected", "transport_identified", "firmware_checked", "firmware_ready", "identity_provisioned", "components_detected", "protocol_tested", "calibration_evaluated", "ready")
VERIFICATION_STATES = frozenset({"supported", "protocol_verified", "electrically_verified", "physically_verified", "calibrated", "not_tested", "failed", "ambiguous"})
 # The pinned firmware exposes raw ADC readings but no calibration command or
 # procedure. Calibration records may be evaluated by a future commissioning
 # tool, but this runtime must not claim a firmware-supported calibration.
CALIBRATION_TYPES = frozenset()

PROTOCOL_TESTS = ("communication", "identity", "temperature_sensor", "heater_command_path",
                  "stir_command_path", "od_led_command_path", "photodiode_read", "pump_channels",
                  "channel_mapping", "safe_shutdown")

def protocol_test_plan() -> list[dict[str, Any]]:
    """Return the bounded test plan; actuator entries require physical opt-in."""
    return [{"name": name, "physical_required": name in {"heater_command_path", "stir_command_path", "od_led_command_path", "pump_channels"},
             "default": "protocol_only"} for name in PROTOCOL_TESTS]
_TRANSITIONS = {left: right for left, right in zip(COMMISSIONING_STATES, COMMISSIONING_STATES[1:])}

def advance_commissioning(record: dict[str, Any], action: str, *, evidence: str = "not_tested") -> dict[str, Any]:
    current = record.get("state", "detected")
    if current not in COMMISSIONING_STATES or action not in {"detect", "initialize", "firmware_check", "firmware_ready", "assign_identity", "inventory", "protocol_test", "calibration_evaluate", "commission"}:
        raise ValueError("invalid commissioning state or action")
    if action == "commission":
        if current != "calibration_evaluated" or evidence not in {"calibrated", "physically_verified"}:
            raise ValueError("commission requires evaluated physical or calibration evidence")
        next_state = "ready"
    else:
        next_state = _TRANSITIONS.get(current)
        if next_state is None: raise ValueError("commissioning is already ready")
    if evidence not in VERIFICATION_STATES: raise ValueError("invalid verification state")
    return {**record, "state": next_state, "verification_state": evidence}

def calibration_staleness(record: dict[str, Any], *, now: datetime | None = None, component_fingerprint: str | None = None, max_age_days: int = 180) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    reasons: list[str] = []
    created = record.get("created_at")
    try:
        at = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        if now - at > timedelta(days=max_age_days): reasons.append("age")
    except (TypeError, ValueError):
        reasons.append("age")
    if component_fingerprint and record.get("hardware_fingerprint") and record["hardware_fingerprint"] != component_fingerprint:
        reasons.append("hardware_identity_changed")
    return {**record, "staleness": "stale" if reasons else "valid", "stale_reasons": reasons, "advisory_only": True}

def assignment_warning(calibration: dict[str, Any], *, active_run: bool = False) -> dict[str, Any]:
    stale = calibration.get("staleness") == "stale"
    return {"warning": stale, "reasons": list(calibration.get("stale_reasons", [])), "active_run_uninterrupted": bool(active_run and stale), "requires_operator_ack": stale}
