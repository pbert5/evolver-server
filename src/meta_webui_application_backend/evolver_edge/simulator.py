"""Deterministic, hardware-free eVOLVER execution simulator."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from typing import Any, Mapping, Sequence
from uuid import NAMESPACE_URL, uuid5

from .store import EdgeStore, EdgeStoreError, Json
from .actuator import RunActuatorExecutor, SimulatorDeviceCommandSink, compile_device_command


@dataclass(frozen=True)
class SimulatedInstrument:
    """Stable simulated hardware inventory owned by one edge controller."""

    id: str
    controller_id: str
    vial_position_ids: tuple[str, ...]
    instrument_type: str = "simulator"
    connection_state: str = "connected"


def _number(value: Any, *, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise EdgeStoreError(f"simulator {field} must be numeric")
    return float(value)


def _duration_seconds(value: Any) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str):
        raise EdgeStoreError("transition after must be seconds or a duration such as '5m'")
    units = {"s": 1.0, "m": 60.0, "h": 3600.0}
    try:
        unit = value[-1]
        return float(value[:-1]) * units[unit]
    except (KeyError, ValueError) as error:
        raise EdgeStoreError(f"unsupported simulator duration: {value!r}") from error


class EvolverSimulator:
    """A restart-safe deterministic declarative-state-machine runner.

    Virtual time is derived from persisted telemetry sequence numbers.  On a
    process restart a freshly constructed simulator therefore advances exactly
    as the previous instance would have; no in-memory clock is authoritative.
    """

    def __init__(self, store: EdgeStore, *, instruments: int = 1,
                 vials_per_instrument: int = 16, seed: int = 0,
                 tick_seconds: float = 60.0) -> None:
        if instruments < 1 or vials_per_instrument < 1 or tick_seconds <= 0:
            raise ValueError("instruments, vial positions, and tick_seconds must be positive")
        self.store = store
        self.seed = seed
        self.tick_seconds = float(tick_seconds)
        controller_id = store.identity()["id"]
        self.instruments = tuple(self._inventory(controller_id, instruments, vials_per_instrument))
        self.device_sink = SimulatorDeviceCommandSink()
        self.actuator_executor = RunActuatorExecutor(store, self.device_sink)
        # The simulator uses exactly the durable Instrument contract that a
        # hardware adapter uses.  Discovery may update observations, but never
        # makes a port/connection status part of device identity.
        self.store.register_instruments(self.inventory())

    @staticmethod
    def _inventory(controller_id: str, count: int, vials: int) -> list[SimulatedInstrument]:
        inventory: list[SimulatedInstrument] = []
        for index in range(count):
            instrument_id = str(uuid5(NAMESPACE_URL, f"evolver-simulator/{controller_id}/instrument/{index}"))
            positions = tuple(str(uuid5(NAMESPACE_URL, f"{instrument_id}/vial/{vial}")) for vial in range(vials))
            inventory.append(SimulatedInstrument(instrument_id, controller_id, positions))
        return inventory

    def inventory(self) -> list[Json]:
        return [{"id": item.id, "controller_id": item.controller_id,
                 "instrument_type": item.instrument_type, "connection_state": item.connection_state,
                 "transport": {"kind": "simulated"},
                 "transport_evidence": {"event": "connected", "simulated": True},
                 "effective_device_state": self.device_state(item.id),
                 "capabilities": {"od_read": {"verification": "protocol_verified"},
                                  "temperature_read": {"verification": "protocol_verified"},
                                  "stir_control": {"verification": "not_tested"},
                                  "pump_control": {"verification": "not_tested"},
                                  "heater_control": {"verification": "not_tested"}},
                 "vial_positions": [{"id": vial, "instrument_id": item.id, "position_index": index}
                                    for index, vial in enumerate(item.vial_position_ids)]}
                for item in self.instruments]

    def device_state(self, instrument_id: str) -> Json:
        """Return deterministic effective device state without hardware I/O."""
        self._instrument(instrument_id)
        return self.device_sink.state(instrument_id)

    def start_run(self, *, run_id: str, bundle_id: str, instrument_ids: Sequence[str] | None = None) -> Json:
        """Create a running simulated run from an immutable declarative bundle."""
        bundle = self.store.bundle(bundle_id)
        if bundle.get("execution_mode") != "declarative_state_machine":
            raise EdgeStoreError("simulator only executes declarative_state_machine bundles")
        plan = self._plan(bundle)
        selected = list(instrument_ids or [item.id for item in self.instruments])
        known = {item.id for item in self.instruments}
        if not selected or not set(selected) <= known:
            raise EdgeStoreError("run targets an instrument not owned by this simulator")
        initial = self._initial_state(plan)
        # Reject predictable protocol/capability errors before creating a run.
        # This is a pure validation pass and does not touch the sink.
        for state_name, state_spec in self._states(plan).items():
            for actions in (self._entry_actions(plan, state_name), self._exit_actions(plan, state_name)):
                for index, action in enumerate(actions):
                    if isinstance(action, Mapping) and (action.get("kind") is not None or "record" not in action):
                        if not isinstance(action, Mapping):
                            raise EdgeStoreError("execution actions must be objects")
                        target = action.get("target") if isinstance(action.get("target"), Mapping) else {}
                        target_instrument = target.get("instrument_id", selected[0])
                        if target_instrument not in selected:
                            raise EdgeStoreError("action target instrument is not assigned to this run")
                        if action.get("operation") in {"pump_pulse", "pump_stop"}:
                            channel = target.get("channel", action.get("parameters", {}).get("channel"))
                            effective = self.store.instrument(target_instrument).get("effective_device_state", {})
                            pump_channels = effective.get("pump", {}).get("channels", {}) if isinstance(effective, Mapping) else {}
                            fault = pump_channels.get(str(channel), {}) if isinstance(pump_channels, Mapping) else {}
                            if isinstance(fault, Mapping) and fault.get("effective_state") == "fault":
                                raise EdgeStoreError(f"pump channel {channel} is faulted")
                        compile_device_command(action, command_id=f"preflight-{state_name}-{index}", run_id=run_id,
                                               run_revision=0, bundle_id=bundle_id, state=state_name,
                                               instrument_id=target_instrument)
        effective = {"bundle_id": bundle_id, "runtime_parameters": {}, "state": "running",
                     "simulator": {"current_state": initial, "state_entered_tick": 0}}
        run = self.store.create_run(run_id=run_id, bundle_id=bundle_id, instrument_ids=selected,
                                    state="running", effective_state=effective)
        self.store.append_event(run_id=run_id, event_type="run_started", revision=0,
                                details={"simulator": True, "state": initial,
                                         "entry_actions": self._entry_actions(plan, initial)})
        self.actuator_executor.execute_actions(run=self.store.run(run_id), state=initial, revision=0,
                                               actions=self._entry_actions(plan, initial))
        return self.store.run(run_id)

    def apply_patch(self, patch: Mapping[str, Any]) -> Json:
        """Apply a revision-safe operator patch, normalizing pause/resume state."""
        value = dict(patch)
        kind = value.get("patch_kind")
        if kind == "pause":
            value["change"] = {**dict(value.get("change", {})), "state": "paused"}
        elif kind == "resume":
            value["change"] = {**dict(value.get("change", {})), "state": "running"}
        revision = self.store.apply_patch(value)
        if kind in {"pause", "resume"}:
            if kind == "pause":
                run = self.store.run(value["run_id"])
                self.actuator_executor.execute_actions(run=run, state="paused", revision=revision["revision"],
                                                       actions=[{"action_id": "pause-safe-stop", "kind": "device_command",
                                                                 "operation": "safe_stop", "target": {"instrument_id": run["instrument_ids"][0]},
                                                                 "parameters": {}}])
            self.store.append_event(run_id=value["run_id"], event_type=f"run_{kind}d" if kind == "pause" else "run_resumed",
                                    revision=revision["revision"], details={"simulator": True})
        elif kind == "stop":
            run = self.store.run(value["run_id"])
            self.actuator_executor.execute_actions(run=run, state="stopped", revision=revision["revision"],
                                                   actions=[{"action_id": "stop-safe-stop", "kind": "device_command",
                                                             "operation": "safe_stop", "target": {"instrument_id": run["instrument_ids"][0]},
                                                             "parameters": {}}])
            self.store.transition_run(run_id=value["run_id"], state="stopped",
                                      based_on_revision=revision["revision"])
        return revision

    def tick(self, *, run_ids: Sequence[str] | None = None, ticks: int = 1) -> list[Json]:
        """Advance selected running runs by virtual ticks without network or hardware."""
        if ticks < 1:
            raise ValueError("ticks must be positive")
        selected = set(run_ids) if run_ids is not None else None
        output: list[Json] = []
        for _ in range(ticks):
            for run in self.store.list_runs():
                if selected is None or run["id"] in selected:
                    output.extend(self.tick_run(run["id"]))
        return output

    def tick_run(self, run_id: str) -> list[Json]:
        """Record a telemetry sample for every target vial and evaluate transitions."""
        run = self.store.run(run_id)
        effective = run["effective_state"]
        if effective.get("state") != "running":
            return []
        self.device_sink.advance(int(self.tick_seconds * 1000))
        bundle = self.store.bundle(run["bundle_id"])
        plan = self._plan(bundle)
        state = effective.get("simulator", {}).get("current_state", self._initial_state(plan))
        samples: list[Json] = []
        for instrument_id in run["instrument_ids"]:
            instrument = self._instrument(instrument_id)
            for vial_index, vial_id in enumerate(instrument.vial_position_ids):
                stream = f"run:{run_id}:instrument:{instrument_id}:vial:{vial_id}"
                prior = self.store.telemetry_after(stream)
                sequence = prior[-1]["sequence"] + 1 if prior else 1
                payload = self._telemetry(run_id, instrument_id, vial_index, sequence)
                samples.append(self.store.spool_telemetry(stream_id=stream, sequence=sequence, payload=payload,
                                                          captured_at=f"simulated+{sequence * self.tick_seconds:.3f}s"))
        self._transition_if_ready(run_id, plan, state)
        return samples

    def _transition_if_ready(self, run_id: str, plan: Mapping[str, Any], current_state: str) -> None:
        run = self.store.run(run_id)
        state_spec = self._states(plan)[current_state]
        simulator = run["effective_state"].get("simulator", {})
        entered = int(simulator.get("state_entered_tick", 0))
        tick = self._run_tick(run)
        if state_spec.get("terminal", False):
            return
        transitions = state_spec.get("transitions", [])
        if not isinstance(transitions, list):
            raise EdgeStoreError("state transitions must be a list")
        for transition in transitions:
            if not isinstance(transition, Mapping) or not isinstance(transition.get("to"), str):
                raise EdgeStoreError("each simulator transition needs a string 'to'")
            condition = transition.get("when")
            ready = self._condition_ready(run, condition) if condition is not None else False
            if "after" in transition:
                ready = ready or (tick - entered) * self.tick_seconds >= _duration_seconds(transition["after"])
            if ready:
                next_state = transition["to"]
                if next_state not in self._states(plan):
                    raise EdgeStoreError(f"transition targets unknown state {next_state!r}")
                # Exit effects are completed before the durable state change;
                # a failure leaves the run in its current state with evidence.
                self.actuator_executor.execute_actions(run=run, state=current_state,
                                                       revision=run["current_revision"],
                                                       actions=self._exit_actions(plan, current_state))
                revision = self.store.apply_patch({"run_id": run_id, "based_on_revision": run["current_revision"],
                                                   "patch_kind": "conditional_logic_change",
                                                   "change": {"simulator": {"current_state": next_state,
                                                                            "state_entered_tick": tick}}})
                self.store.append_event(run_id=run_id, event_type="condition_reached", revision=revision["revision"],
                                        details={"from": current_state, "to": next_state, "transition": dict(transition),
                                                 "simulator": True,
                                                 "exit_actions": self._exit_actions(plan, current_state),
                                                 "entry_actions": self._entry_actions(plan, next_state)})
                self.actuator_executor.execute_actions(run=self.store.run(run_id), state=next_state,
                                                       revision=revision["revision"],
                                                       actions=self._entry_actions(plan, next_state))
                return

    def _condition_ready(self, run: Mapping[str, Any], condition: Any) -> bool:
        """Evaluate only structured declarative predicates; never execute code."""
        if not isinstance(condition, Mapping):
            raise EdgeStoreError("transition when must be a declarative mapping")
        if "all" in condition:
            values = condition["all"]
            if not isinstance(values, list): raise EdgeStoreError("condition all must be a list")
            return all(self._condition_ready(run, value) for value in values)
        if "any" in condition:
            values = condition["any"]
            if not isinstance(values, list): raise EdgeStoreError("condition any must be a list")
            return any(self._condition_ready(run, value) for value in values)
        if "not" in condition:
            return not self._condition_ready(run, condition["not"])
        if "od_gte" in condition:  # legacy shorthand retained in immutable bundles
            return self._run_od(run) >= _number(condition["od_gte"], field="od_gte")
        if "sensor" in condition:
            sensor = condition["sensor"]
            if sensor not in {"od", "temperature_c"}: raise EdgeStoreError(f"unsupported simulated sensor {sensor!r}")
            actual = self._run_sensor(run, sensor)
            return self._comparison(actual, condition, subject=f"sensor {sensor}")
        if "runtime_parameter" in condition:
            key = condition["runtime_parameter"]
            if not isinstance(key, str): raise EdgeStoreError("runtime_parameter must be a string")
            parameters = run["effective_state"].get("runtime_parameters", {})
            if not isinstance(parameters, Mapping) or key not in parameters:
                return False
            return self._comparison(_number(parameters[key], field=f"runtime parameter {key}"), condition,
                                    subject=f"runtime parameter {key}")
        raise EdgeStoreError("unsupported declarative transition condition")

    @staticmethod
    def _comparison(actual: float, condition: Mapping[str, Any], *, subject: str) -> bool:
        operators = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b,
                     "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b,
                     "eq": lambda a, b: a == b}
        selected = [(name, value) for name, value in condition.items() if name in operators]
        if len(selected) != 1: raise EdgeStoreError(f"{subject} condition requires exactly one comparison")
        name, value = selected[0]
        return operators[name](actual, _number(value, field=f"{subject} {name}"))

    def _run_tick(self, run: Mapping[str, Any]) -> int:
        instrument = self._instrument(run["instrument_ids"][0])
        vial = instrument.vial_position_ids[0]
        stream = f"run:{run['id']}:instrument:{instrument.id}:vial:{vial}"
        records = self.store.telemetry_after(stream)
        return records[-1]["sequence"] if records else 0

    def _run_od(self, run: Mapping[str, Any]) -> float:
        return self._run_sensor(run, "od")

    def _run_sensor(self, run: Mapping[str, Any], sensor: str) -> float:
        instrument = self._instrument(run["instrument_ids"][0])
        stream = f"run:{run['id']}:instrument:{instrument.id}:vial:{instrument.vial_position_ids[0]}"
        records = self.store.telemetry_after(stream)
        return float(records[-1]["payload"].get(sensor, 0.0)) if records else 0.0

    def _telemetry(self, run_id: str, instrument_id: str, vial_index: int, sequence: int) -> Json:
        # The digest-derived phase avoids Python's randomized hash while making
        # trajectories stable for a supplied seed and distinct for each vial.
        material = f"{self.seed}/{run_id}/{instrument_id}/{vial_index}".encode()
        phase = int(hashlib.sha256(material).hexdigest()[:8], 16) / 0xFFFFFFFF
        od = min(1.2, 0.05 + sequence * 0.06 + vial_index * 0.002 + phase * 0.001)
        temperature_c = 30.0 + math.sin(sequence / 8.0 + phase * math.pi) * 0.15
        return {"od": round(od, 6), "temperature_c": round(temperature_c, 6),
                "simulated": True, "tick": sequence,
                "effective_device_state": self.device_state(instrument_id)}

    @staticmethod
    def _plan(bundle: Mapping[str, Any]) -> Mapping[str, Any]:
        plan = bundle.get("execution_plan")
        # LinkML's SerializedPayload is normally {content, media_type}; direct
        # mappings are retained for old edge fixtures and hand-authored bundles.
        if isinstance(plan, Mapping) and isinstance(plan.get("content"), Mapping):
            plan = plan["content"]
        if not isinstance(plan, Mapping):
            raise EdgeStoreError("declarative simulator bundle requires an execution_plan mapping")
        EvolverSimulator._states(plan)
        return plan

    @classmethod
    def _entry_actions(cls, plan: Mapping[str, Any], state: str) -> list[Any]:
        """Return declarative entry actions from the immutable plan."""
        actions = cls._states(plan)[state].get("entry_actions", [])
        if not isinstance(actions, list):
            raise EdgeStoreError("state entry_actions must be a list")
        return list(actions)

    @classmethod
    def _exit_actions(cls, plan: Mapping[str, Any], state: str) -> list[Any]:
        actions = cls._states(plan)[state].get("exit_actions", [])
        if not isinstance(actions, list):
            raise EdgeStoreError("state exit_actions must be a list")
        return list(actions)

    @staticmethod
    def _states(plan: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
        states = plan.get("states")
        if not isinstance(states, Mapping) or not states or not all(isinstance(v, Mapping) for v in states.values()):
            raise EdgeStoreError("execution_plan.states must be a non-empty mapping")
        return states  # type: ignore[return-value]

    @classmethod
    def _initial_state(cls, plan: Mapping[str, Any]) -> str:
        initial = plan.get("initial_state") or plan.get("initial") or next(iter(cls._states(plan)))
        if not isinstance(initial, str) or initial not in cls._states(plan):
            raise EdgeStoreError("execution_plan initial_state must name a state")
        return initial

    def _instrument(self, instrument_id: str) -> SimulatedInstrument:
        for item in self.instruments:
            if item.id == instrument_id:
                return item
        raise EdgeStoreError(f"unknown simulated instrument {instrument_id}")
