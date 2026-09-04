"""Edge-local, typed run actuation with durable replay identity.

This module is deliberately transport-neutral.  A sink receives only the
evolver.device.v2 command object; it never receives an unvalidated bundle
action or executable code.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from typing import Any, Callable, Mapping, Protocol
from uuid import NAMESPACE_URL, uuid5

from .hardware import DEVICE_PROTOCOL_VERSION, HardwareService, validate_device_operation
from .store import EdgeStore, EdgeStoreError, StaleGenerationError


class DeviceCommandSink(Protocol):
    def send(self, command: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _command_time(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise EdgeStoreError("manual command expiry is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EdgeStoreError("manual command expiry is invalid") from error
    if parsed.tzinfo is None:
        raise EdgeStoreError("manual command expiry must include a timezone")
    return parsed.astimezone(UTC)


@dataclass
class ManualCommandExecutor:
    """Execute centrally queued manual intent through the typed device sink.

    The executor is deliberately optional at the sync boundary: an edge with
    no hardware service can still journal the intent, while a configured
    typed sink can perform the operation.  Completed command ids are retained
    by ``EdgeStore`` so delivery retries never repeat a pulse.
    """

    store: EdgeStore
    sink: DeviceCommandSink
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)

    def execute(self, command: Mapping[str, Any]) -> dict[str, Any]:
        command_id = command.get("command_id")
        if not isinstance(command_id, str) or not command_id:
            return {"command_id": command_id, "disposition": "rejected_invalid", "reason": "command_id required"}
        try:
            return self.store.execute_command(command, lambda: self._execute_uncached(command))
        except StaleGenerationError:
            result = self._execute_uncached(command)
            return self.store.acknowledge_command(command, result)

    def _execute_uncached(self, command: Mapping[str, Any]) -> dict[str, Any]:
        command_id = command.get("command_id")
        generation = command.get("controller_generation")
        binding = self.store.binding()
        if isinstance(generation, bool) or not isinstance(generation, int) or not isinstance(binding, Mapping) \
                or generation <= 0 or generation != binding.get("generation"):
            return {"command_id": command_id, "disposition": "rejected_stale_generation"}
        try:
            if self.clock().astimezone(UTC) >= _command_time(command.get("expires_at")):
                return {"command_id": command_id, "disposition": "expired", "expiration_reason": "ttl_expired"}
        except (AttributeError, EdgeStoreError) as error:
            return {"command_id": command_id, "disposition": "rejected_invalid", "reason": str(error)}

        operation = command.get("operation")
        if operation not in {"stir_pulse", "heater_pulse", "safe_stop"}:
            return {"command_id": command_id, "disposition": "rejected_invalid", "reason": "unsupported manual operation"}
        if operation != "safe_stop":
            if not all(isinstance(command.get(key), str) and command[key] for key in ("lease_token", "lease_holder")):
                return {"command_id": command_id, "disposition": "rejected_lease", "reason": "active lease is required"}
            try:
                self.store.validate_control_lease(lease_token=command["lease_token"], owner=command["lease_holder"], generation=generation)
            except Exception as error:
                return {"command_id": command_id, "disposition": "rejected_lease", "reason": str(error)}

        instrument_id = command.get("instrument_id")
        target = command.get("target") if isinstance(command.get("target"), Mapping) else {}
        instrument_id = instrument_id or target.get("instrument_id")
        run_id = command.get("run_id")
        if run_id is not None:
            if not isinstance(run_id, str):
                return {"command_id": command_id, "disposition": "rejected_invalid", "reason": "run_id must be a string"}
            try:
                run = self.store.run(run_id)
            except (KeyError, EdgeStoreError):
                return {"command_id": command_id, "disposition": "rejected_run_ownership", "reason": "run is not present locally"}
            if run.get("state") not in {"running", "paused", "stopping"} or instrument_id not in run.get("instrument_ids", []):
                return {"command_id": command_id, "disposition": "rejected_run_ownership", "reason": "run does not own target instrument"}
        if operation != "safe_stop" and not isinstance(instrument_id, str):
            return {"command_id": command_id, "disposition": "rejected_invalid", "reason": "instrument_id is required"}
        parameters = dict(command.get("parameters") or {})
        if operation == "heater_pulse":
            # Device protocol v2 is intentionally narrower than the central
            # preview envelope: never pass an unbounded heater request onward.
            if not isinstance(parameters.get("duration_ms"), int) or not 1 <= parameters["duration_ms"] <= 250 \
                    or not isinstance(parameters.get("level"), int) or not 1 <= parameters["level"] <= 64:
                return {"command_id": command_id, "disposition": "rejected_invalid", "reason": "heater pulse exceeds device safety bounds"}
            operation_for_device = "pulse_heater"
        elif operation in {"stir_pulse", "set_stir"}:
            if not isinstance(parameters.get("duration_ms"), int) or not 1 <= parameters["duration_ms"] <= 1000 \
                    or not isinstance(parameters.get("level"), int) or not 1 <= parameters["level"] <= 250:
                return {"command_id": command_id, "disposition": "rejected_invalid", "reason": "stir pulse exceeds device safety bounds"}
            operation_for_device = "set_stir"
        else:
            operation_for_device = "safe_stop"
        typed = {"schema_version": DEVICE_PROTOCOL_VERSION, "command_id": command_id,
                 "operation": operation_for_device,
                 "target": {"instrument_id": instrument_id, "device_id": target.get("device_id", instrument_id)},
                 "parameters": parameters,
                 "context": {"run_id": run_id, "controller_generation": generation,
                             "lease_token": command.get("lease_token"), "lease_owner": command.get("lease_holder")}}
        try:
            result = dict(self.sink.send(typed))
        except Exception as error:
            return {"command_id": command_id, "disposition": "failed", "reason": str(error)}
        return {"command_id": command_id, "disposition": "completed", "result": result}


def _int(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise EdgeStoreError(f"{name} must be an integer in {low}..{high}")
    return value


def compile_device_command(action: Mapping[str, Any], *, command_id: str,
                           run_id: str, run_revision: int, bundle_id: str,
                           state: str, instrument_id: str,
                           controller_generation: int = 0) -> dict[str, Any]:
    if isinstance(controller_generation, bool) or not isinstance(controller_generation, int) \
            or controller_generation < 0:
        raise EdgeStoreError("controller_generation must be a non-negative integer")
    if action.get("kind", "device_command") != "device_command":
        raise EdgeStoreError("only declarative device_command actions are executable")
    operation = action.get("operation")
    target = action.get("target") if isinstance(action.get("target"), Mapping) else {}
    parameters = action.get("parameters") if isinstance(action.get("parameters"), Mapping) else {}
    target_instrument = target.get("instrument_id", instrument_id)
    if target_instrument != instrument_id:
        raise EdgeStoreError("action target instrument is not assigned to this run")
    if operation == "pump_pulse":
        channel = _int(target.get("channel", parameters.get("channel")), "pump channel", 0, 5)
        duration = _int(parameters.get("duration_ms"), "pump duration_ms", 1, 1000)
        params = {"channel": channel, "direction": parameters.get("direction", "forward"), "duration_ms": duration}
        if params["direction"] != "forward":
            raise EdgeStoreError("reverse pumping is unsupported")
    elif operation == "stir_pulse":
        if "rpm" in parameters:
            raise EdgeStoreError("stir RPM control is unsupported; use PWM level")
        channel = _int(target.get("channel", parameters.get("channel")), "stir channel", 0, 1)
        params = {"channel": channel,
                  "level": _int(parameters.get("level"), "stir level", 1, 250),
                  "duration_ms": _int(parameters.get("duration_ms"), "stir duration_ms", 1, 1000)}
    elif operation == "pump_stop":
        params = {"channel": _int(target.get("channel", parameters.get("channel")), "pump channel", 0, 5)}
    elif operation == "safe_stop":
        params = {}
    else:
        raise EdgeStoreError(f"unsupported run device operation: {operation}")
    protocol_operation = {"pump_pulse": "pulse_pump", "stir_pulse": "set_stir",
                          "pump_stop": "pulse_pump", "safe_stop": "safe_stop"}[operation]
    try:
        validate_device_operation(protocol_operation, params)
    except (ValueError, KeyError) as error:
        raise EdgeStoreError(str(error)) from error
    return {"schema_version": DEVICE_PROTOCOL_VERSION, "command_id": command_id,
            "operation": operation, "target": {"device_id": instrument_id, "instrument_id": instrument_id},
            "parameters": params,
            "context": {"run_id": run_id, "run_revision": run_revision, "bundle_id": bundle_id,
                         "execution_state": state, "action_id": action.get("action_id"),
                         "controller_generation": controller_generation}}


@dataclass
class RunActuatorExecutor:
    store: EdgeStore
    sink: DeviceCommandSink

    def command_id(self, run_id: str, revision: int, state: str, index: int, action: Mapping[str, Any]) -> str:
        action_id = action.get("action_id", f"{state}:{index}")
        return str(uuid5(NAMESPACE_URL, f"evolver-run-action/{run_id}/{revision}/{state}/{action_id}"))

    def execute_actions(self, *, run: Mapping[str, Any], state: str,
                        revision: int, actions: list[Any]) -> list[Mapping[str, Any]]:
        results: list[Mapping[str, Any]] = []
        binding = self.store.binding()
        generation = binding.get("generation") if isinstance(binding, Mapping) else None
        valid_generation = (isinstance(generation, int) and not isinstance(generation, bool)
                            and generation > 0)
        if isinstance(self.sink, HardwareDeviceCommandSink) and not valid_generation:
            raise EdgeStoreError("hardware run command requires a positive controller generation")
        command_generation = generation if valid_generation else 0
        for index, raw in enumerate(actions):
            if not isinstance(raw, Mapping):
                raise EdgeStoreError("execution actions must be objects")
            # Existing non-actuating journal annotations remain compatible.
            if raw.get("kind") is None and "record" in raw:
                continue
            instrument_id = raw.get("target", {}).get("instrument_id") if isinstance(raw.get("target"), Mapping) else None
            instrument_id = instrument_id or run["instrument_ids"][0]
            if instrument_id not in run["instrument_ids"]:
                raise EdgeStoreError("action resource is not assigned to the run")
            command_id = self.command_id(run["id"], revision, state, index, raw)
            command = compile_device_command(raw, command_id=command_id, run_id=run["id"],
                                             run_revision=revision, bundle_id=run["bundle_id"],
                                             state=state, instrument_id=instrument_id,
                                             controller_generation=command_generation)
            existing = self.store.run_action(command_id)
            if existing:
                if existing.get("request") != command:
                    raise EdgeStoreError(f"command id collision for run action {command_id}")
                status = existing.get("status")
                if status == "acknowledged":
                    results.append(existing.get("result") or {})
                    continue
                if status in {"rejected", "failed"}:
                    raise EdgeStoreError(f"run action {command_id} previously {status}; operator review required")
                raise EdgeStoreError(f"run action {command_id} is pending; refusing ambiguous replay")
            self.store.record_run_action(command_id=command_id, run_id=run["id"],
                                         action_id=str(raw.get("action_id", f"{state}:{index}")),
                                         state=state, revision=revision, operation=command["operation"], request=command)
            try:
                result = dict(self.sink.send(command))
                status = "acknowledged" if result.get("request_accepted", True) else "rejected"
                self.store.complete_run_action(command_id, status=status, result=result)
                self.store.append_event(run_id=run["id"], event_type="run_action_result", revision=revision,
                                        details={"action_id": command["context"]["action_id"], "operation": command["operation"],
                                                 "status": status, "protocol_result": result}, causation_command_id=command_id)
                results.append(result)
            except Exception as error:
                self.store.complete_run_action(command_id, status="failed", result={"error": str(error)})
                self.store.append_event(run_id=run["id"], event_type="run_action_failed", revision=revision,
                                        details={"action_id": command["context"]["action_id"], "error": str(error)},
                                        causation_command_id=command_id)
                raise
        return results


class SimulatorDeviceCommandSink:
    """Deterministic sink; no sleep, serial, network, or real hardware."""
    def __init__(self) -> None:
        self.now_ms = 0
        self.outputs: dict[tuple[str, str, int], dict[str, Any]] = {}
        self.commands: list[dict[str, Any]] = []
        self._results: dict[str, Mapping[str, Any]] = {}

    def send(self, command: Mapping[str, Any]) -> Mapping[str, Any]:
        if command.get("command_id") in self._results:
            return self._results[str(command["command_id"])]
        if command.get("schema_version") != DEVICE_PROTOCOL_VERSION:
            raise EdgeStoreError("unsupported device protocol")
        operation = command.get("operation")
        target = command.get("target", {})
        instrument_id = target.get("instrument_id")
        p = command.get("parameters", {})
        if operation == "pump_pulse":
            _int(p.get("channel"), "pump channel", 0, 5); _int(p.get("duration_ms"), "duration_ms", 1, 1000)
            if p.get("direction") != "forward": raise EdgeStoreError("reverse pumping is unsupported")
            key = (instrument_id, "pump", p["channel"])
            self.outputs[key] = {"effective_state": "active", "direction": "forward", "owner": "run",
                                 "command_id": command["command_id"], "duration_ms": p["duration_ms"],
                                 "active_until_ms": self.now_ms + p["duration_ms"], "evidence": "simulated"}
        elif operation in {"stir_pulse", "set_stir"}:
            _int(p.get("channel"), "stir channel", 0, 1); _int(p.get("level"), "level", 1, 250); _int(p.get("duration_ms"), "duration_ms", 1, 1000)
            key = (instrument_id, "stir", p["channel"])
            self.outputs[key] = {"effective_state": "active", "pwm_level": p["level"], "owner": "run",
                                 "command_id": command["command_id"], "duration_ms": p["duration_ms"],
                                 "active_until_ms": self.now_ms + p["duration_ms"], "evidence": "simulated"}
        elif operation in {"pulse_heater", "heater_pulse"}:
            _int(p.get("channel"), "heater channel", 0, 1); _int(p.get("level"), "level", 1, 64); _int(p.get("duration_ms"), "duration_ms", 1, 250)
            key = (instrument_id, "heater", p["channel"])
            self.outputs[key] = {"effective_state": "active", "level": p["level"], "owner": "manual",
                                 "command_id": command["command_id"], "duration_ms": p["duration_ms"],
                                 "active_until_ms": self.now_ms + p["duration_ms"], "evidence": "simulated"}
        elif operation == "pump_stop":
            self.outputs.pop((instrument_id, "pump", p["channel"]), None)
        elif operation == "safe_stop":
            self.outputs.clear()
        else:
            raise EdgeStoreError(f"unsupported device operation: {operation}")
        self.commands.append(dict(command))
        result = {"command_id": command["command_id"], "request_accepted": True,
                "protocol_response": f"SIMULATED|{operation}", "verification": "simulated_effective_state",
                "observed_evidence": {"simulated": True}}
        self._results[str(command["command_id"])] = result
        return result

    def advance(self, milliseconds: int) -> None:
        self.now_ms += milliseconds
        self.outputs = {key: value for key, value in self.outputs.items() if value["active_until_ms"] > self.now_ms}

    def state(self, instrument_id: str) -> dict[str, Any]:
        pumps = {str(channel): value for (instrument, kind, channel), value in self.outputs.items()
                 if instrument == instrument_id and kind == "pump"}
        stirs = {str(channel): value for (instrument, kind, channel), value in self.outputs.items()
                 if instrument == instrument_id and kind == "stir"}
        heaters = {str(channel): value for (instrument, kind, channel), value in self.outputs.items()
                   if instrument == instrument_id and kind == "heater"}
        return {"pump": {"effective_state": "active" if pumps else "inactive", "channels": pumps, "evidence": "simulated"},
                "stir": {"effective_state": "active" if stirs else "inactive", "channels": stirs, "evidence": "simulated"},
                "heater": {"effective_state": "active" if heaters else "inactive", "channels": heaters, "evidence": "simulated"},
                "temperature": {"effective_state": "inactive", "evidence": "simulated"}}


class HardwareDeviceCommandSink:
    """Adapter to the existing exclusive HardwareService boundary.

    Meta owns no wire grammar here: the service performs protocol validation,
    lease fencing, frame construction, and transport dispatch.
    """
    def __init__(self, store: EdgeStore, service: HardwareService) -> None:
        self.store, self.service = store, service

    def send(self, command: Mapping[str, Any]) -> Mapping[str, Any]:
        if command.get("schema_version") != DEVICE_PROTOCOL_VERSION:
            raise EdgeStoreError("unsupported device protocol")
        if command.get("operation") == "pump_stop":
            raise EdgeStoreError("pump_stop is not supported by physical hardware; use safe_stop")
        target = command.get("target", {})
        instrument_id = target.get("instrument_id")
        instruments = self.store.list_instruments() if command.get("operation") == "safe_stop" else [self.store.instrument(instrument_id)]
        operation = {"pump_pulse": "pulse_pump", "stir_pulse": "set_stir",
                     "heater_pulse": "pulse_heater", "safe_stop": "safe_stop"}[command["operation"]]
        parameters = dict(command.get("parameters", {}))
        context = command.get("context", {})
        generation = context.get("controller_generation")
        binding = self.store.binding()
        if (isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0
                or not isinstance(binding, Mapping) or generation != binding.get("generation")):
            raise EdgeStoreError("hardware command requires the active positive controller generation")
        results = []
        for index, instrument in enumerate(instruments):
            device_identity = instrument.get("device_identity")
            if not isinstance(device_identity, str) or not device_identity:
                raise EdgeStoreError("instrument has no provisioned device identity; safe stop is not confirmed for all instruments")
            result = self.service.command(operation, device_identity, parameters,
                                          command_id=command["command_id"] if index == 0 else f"{command['command_id']}:{index}",
                                          run_id=context.get("run_id"), controller_generation=generation,
                                          lease_token=context.get("lease_token"), lease_owner=context.get("lease_owner"),
                                          require_lease=bool(context.get("lease_token")))
            results.append(result.as_json())
        return results[0] if len(results) == 1 else {"command_id": command["command_id"], "request_accepted": all(item["request_accepted"] for item in results),
                                                      "verification": "protocol_verified", "results": results}
