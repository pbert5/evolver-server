"""Edge-initiated HTTP enrollment and batched synchronization.

The client depends only on :class:`EdgeStore`; a server is an HTTP peer, not a
source of execution truth.  Its small injectable transport makes protocol
tests independent of a web framework.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .actuator import ManualCommandExecutor
from .hardware import HardwareUnavailableError, ReadOnlyHardwareService
from .hardware_ipc import DEFAULT_SOCKET, request as hardware_ipc_request
from .store import EdgeStore, StaleGenerationError

Json = dict[str, Any]
Transport = Callable[[str, Json, dict[str, str], float], tuple[int, Json]]
HardwareRequest = Callable[[Json, float], Json]
MAX_RECORDS_PER_BATCH = 100
MAX_STREAMS_PER_SYNC = 20


def _is_locked_database(error: sqlite3.OperationalError) -> bool:
    """Limit retry handling to SQLite's transient lock condition."""
    return "database is locked" in str(error).lower()


def _post(url: str, body: Json, headers: dict[str, str], timeout: float) -> tuple[int, Json]:
    request = Request(url, data=json.dumps(body, separators=(",", ":")).encode(), method="POST",
                      headers={"content-type": "application/json", **headers})
    try:
        with urlopen(request, timeout=timeout) as response:  # nosec B310: operator-supplied server endpoint
            payload = json.loads(response.read().decode() or "{}")
            return response.status, payload
    except HTTPError as error:
        # HTTP errors are meaningful protocol responses (not a lost central).
        # In particular a 409 carries GenerationConflict and must fence the
        # edge rather than incorrectly moving it into ordinary orphan mode.
        try:
            payload = json.loads(error.read().decode() or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"error": f"HTTP {error.code}"}
        return error.code, payload
    except URLError:
        raise


@dataclass
class SyncResult:
    status: int
    response: Json
    commands_processed: int = 0


class SyncClient:
    """Persistent edge-to-central synchronizer using `/api/evolver/controllers/sync`."""

    def __init__(self, store: EdgeStore, *, transport: Transport = _post, timeout: float = 10.0,
                 manual_executor: ManualCommandExecutor | None = None,
                 hardware_service: ReadOnlyHardwareService | None = None,
                 hardware_request: HardwareRequest | None = None,
                 hardware_socket: str | None = None):
        self.store, self.transport, self.timeout = store, transport, timeout
        self.manual_executor, self.hardware_service = manual_executor, hardware_service
        socket_path = hardware_socket or os.environ.get("EVOLVER_HARDWARE_SOCKET", DEFAULT_SOCKET)
        self.hardware_request = hardware_request or (
            lambda payload, request_timeout: hardware_ipc_request(socket_path, payload, request_timeout)
        )

    def enrollment_plan(self, *, server: str, requested_webui_controller_id: str | None = None) -> Json:
        """Return the non-mutating binding decision shown by ``evoctl``."""
        binding = self.store.binding()
        current = None if not binding else {"server": binding["server_url"], "central_identity": binding["webui_controller_id"],
                                             "generation": binding["generation"], "connectivity": self.store.identity()["connection_state"],
                                             "active_runs": [run["id"] for run in self.store.list_runs() if run.get("state") in {"running", "paused"}]}
        requested = {"server": server.rstrip("/"), "central_identity": requested_webui_controller_id or "resolved by enrollment credential"}
        path = "enrollment" if not binding else ("repair" if requested_webui_controller_id == binding["webui_controller_id"] else "handoff_or_forced_adoption")
        return {"current": current, "requested": requested, "required_path": path}

    def enroll(self, *, server: str, token: str, mode: str | None = None, operator_confirmed: bool = False) -> Json:
        identity = self.store.identity()
        current = self.store.binding()
        if current and mode is None:
            # Never turn a convenient rerun of enrollment into a takeover.
            raise StaleGenerationError("controller is already enrolled; inspect enrollment_plan and explicitly choose repair, live_handoff, or forced_adoption")
        if mode not in {None, "repair", "live_handoff", "forced_adoption"}:
            raise ValueError("mode must be repair, live_handoff, or forced_adoption")
        body: Json = {
            "controller_id": identity["id"], "public_key_fingerprint": identity["public_key_fingerprint"],
            "enrollment_token": token, "binding_mode": mode or "enrollment",
        }
        if current:
            body["current_binding"] = {"webui_controller_id": current["webui_controller_id"], "generation": current["generation"],
                                       "server_url": current["server_url"]}
        if mode == "forced_adoption":
            body["operator_confirmed"] = operator_confirmed
        if mode == "live_handoff":
            release_status, release = self.transport(current["server_url"].rstrip("/") + "/api/evolver/controllers/handoff/release", {
                "controller_id": identity["id"], "target_server_url": server.rstrip("/"),
            }, {"authorization": f"Bearer {current['credential']}"}, self.timeout)
            if release_status >= 400:
                raise RuntimeError(release.get("error", f"live handoff release failed ({release_status})"))
            if release.get("released_generation") != current["generation"]:
                raise StaleGenerationError("old WebUI released an unexpected controller generation")
            body["handoff_released"] = True
        status, response = self.transport(server.rstrip("/") + "/api/evolver/controllers/enroll", {
            **body,
        }, {}, self.timeout)
        if status not in {200, 201}:
            raise RuntimeError(response.get("error", f"enrollment failed ({status})"))
        binding, central = response.get("binding"), response.get("webui_controller")
        if not isinstance(binding, dict) or not isinstance(central, dict) or not response.get("credential"):
            raise RuntimeError("enrollment response lacks durable binding or credential")
        self.store.bind(webui_controller_id=central["id"], server_url=server.rstrip("/"), credential=response["credential"],
                        generation=int(binding["controller_generation"]), status="active",
                        force_adoption=mode in {"live_handoff", "forced_adoption"})
        return response

    def _batch(self, inventory: list[Json] | None = None) -> Json:
        identity, binding = self.store.identity(), self.store.binding()
        if not binding:
            raise RuntimeError("controller is not enrolled")
        # Cursors are acknowledgements, never record counts.  Event sequence
        # numbers are scoped to a run; telemetry sequence numbers to a stream.
        event_batches = []
        for run_id in self.store.event_streams()[:MAX_STREAMS_PER_SYNC]:
            cursor = int(self.store.cursor(f"central:event:{run_id}"))
            records = self.store.events_after(run_id, cursor)[:MAX_RECORDS_PER_BATCH]
            if records:
                event_batches.append({"run_id": run_id, "records": records})
        telemetry_batches = []
        for stream_id in self.store.telemetry_streams()[:MAX_STREAMS_PER_SYNC]:
            cursor = int(self.store.cursor(f"central:telemetry:{stream_id}"))
            records = self.store.telemetry_after(stream_id, cursor)[:MAX_RECORDS_PER_BATCH]
            if records:
                telemetry_batches.append({"stream_id": stream_id, "first_sequence": records[0]["sequence"],
                                          "last_sequence": records[-1]["sequence"], "records": records})
        # The ordinary heartbeat is a compact operational summary.  Full
        # recovery provenance is requested explicitly, not replayed on every
        # synchronization cycle.
        manifest = self.store.recovery_manifest(include_records=False)
        return {
            "controller_id": identity["id"], "controller_generation": binding["generation"],
            "heartbeat": {"state": identity["connection_state"], "at": manifest["generated_at"]},
            "inventory": inventory or [], "hardware_observation": self.store.hardware_observation(),
            "active_runs": manifest["active_runs"], "event_batches": event_batches,
            "command_acknowledgements": self.store.command_acknowledgements(),
            "telemetry_batches": telemetry_batches, "recovery_summary": manifest,
        }

    def sync_once(self, *, inventory: list[Json] | None = None) -> SyncResult:
        binding = self.store.binding()
        if not binding:
            raise RuntimeError("controller is not enrolled")
        try:
            status, response = self.transport(binding["server_url"].rstrip("/") + "/api/evolver/controllers/sync", self._batch(inventory),
                                              {"authorization": f"Bearer {binding['credential']}"}, self.timeout)
        except (OSError, URLError, TimeoutError):
            self.store.set_connection_state("orphaned")
            raise
        if status >= 400:
            if response.get("kind") == "GenerationConflict":
                self.store.set_connection_state("recovery_required")
                raise StaleGenerationError(response.get("error", "central generation conflict"))
            self.store.set_connection_state("orphaned")
            raise RuntimeError(response.get("error", f"sync failed ({status})"))
        central = response.get("webui_controller")
        if isinstance(central, dict) and central.get("id") != binding["webui_controller_id"]:
            self.store.set_connection_state("recovery_required")
            raise StaleGenerationError("server URL now identifies a different WebUI controller")
        if response.get("accepted_generation") != binding["generation"]:
            self.store.set_connection_state("recovery_required")
            raise StaleGenerationError("central accepted an unexpected controller generation")
        self.store.set_connection_state("connected")
        processed = 0
        for command in response.get("commands", []):
            if isinstance(command, dict):
                self._process_command(command); processed += 1
        for prefix, response_name in (("event", "event_cursors"), ("telemetry", "telemetry_cursors")):
            cursors = response.get(response_name)
            if isinstance(cursors, dict):
                for stream_id, value in cursors.items():
                    if isinstance(stream_id, str) and isinstance(value, int):
                        self.store.set_cursor(f"central:{prefix}:{stream_id}", value)
        return SyncResult(status, response, processed)

    def wait_once(self, *, wait_seconds: float = 25.0) -> SyncResult:
        """Wait for one outbound command without replacing ordinary sync."""
        binding = self.store.binding()
        identity = self.store.identity()
        if not binding:
            raise RuntimeError("controller is not enrolled")
        cursor = int(self.store.cursor("central:command"))
        body = {"controller_id": identity["id"], "controller_generation": binding["generation"],
                "last_cursor": cursor, "wait_seconds": max(0.0, min(30.0, float(wait_seconds)))}
        try:
            status, response = self.transport(binding["server_url"].rstrip("/") + "/api/evolver/controllers/commands/wait",
                                              body, {"authorization": f"Bearer {binding['credential']}"},
                                              max(self.timeout, body["wait_seconds"] + 5))
        except (OSError, URLError, TimeoutError):
            self.store.set_connection_state("orphaned")
            raise
        if status >= 400:
            if response.get("kind") == "GenerationConflict":
                self.store.set_connection_state("recovery_required")
                raise StaleGenerationError(response.get("error", "central generation conflict"))
            self.store.set_connection_state("orphaned")
            raise RuntimeError(response.get("error", f"command wait failed ({status})"))
        command = response.get("command")
        processed = 0
        if isinstance(command, dict):
            self._process_command(command)
            processed = 1
            next_cursor = response.get("cursor")
            if isinstance(next_cursor, int) and next_cursor > cursor:
                self.store.set_cursor("central:command", next_cursor)
        self.store.set_connection_state("connected")
        return SyncResult(status, response, processed)

    def _process_command(self, command: Json) -> Json:
        kind = command.get("command_kind")
        def execute() -> Json:
            if kind == "renew_manual_lease":
                required = ("lease_token", "lease_holder", "lease_expires_at")
                if not all(isinstance(command.get(key), str) and command[key] for key in required):
                    return {"command_id": command.get("command_id"), "disposition": "rejected_invalid", "reason": "lease renewal fields required"}
                self.store.set_control_lease(lease_token=command["lease_token"], owner=command["lease_holder"],
                                              generation=int(command.get("controller_generation", 0)),
                                              expires_at=command["lease_expires_at"])
                return {"command_id": command["command_id"], "disposition": "completed", "lease_renewed": True,
                        "controller_generation": command.get("controller_generation")}
            if all(isinstance(command.get(key), str) for key in ("lease_token", "lease_holder", "lease_expires_at")):
                self.store.set_control_lease(lease_token=command["lease_token"], owner=command["lease_holder"],
                                             generation=int(command.get("controller_generation", 0)),
                                             expires_at=command["lease_expires_at"])
            _kind, run_id = kind, command.get("run_id")
            if _kind in {"pause_run", "resume_run", "stop_run", "start_run"}:
                if not isinstance(run_id, str) or not isinstance(command.get("based_on_revision"), int):
                    return {"command_id": command["command_id"], "disposition": "rejected_invalid", "reason": "run_id and based_on_revision required"}
                state = {"pause_run": "paused", "resume_run": "running", "start_run": "running", "stop_run": "stopped"}[_kind]
                run = self.store.transition_run(run_id=run_id, state=state, based_on_revision=command["based_on_revision"], command_id=command["command_id"])
                return {"command_id": command["command_id"], "disposition": "completed", "observed_revision": run["current_revision"]}
            if kind == "apply_run_patch":
                if not isinstance(run_id, str):
                    return {"command_id": command["command_id"], "disposition": "rejected_invalid", "reason": "run_id required"}
                patch = dict(command.get("payload") or {})
                if patch.get("run_id") not in {None, run_id}:
                    return {"command_id": command["command_id"], "disposition": "rejected_invalid", "reason": "patch run_id differs from command target"}
                patch["run_id"] = run_id; patch.setdefault("based_on_revision", command.get("based_on_revision"))
                revision = self.store.apply_patch(patch)
                return {"command_id": command["command_id"], "disposition": "completed", "observed_revision": revision["revision"]}
            if kind == "store_calibration_artifact":
                artifact = command.get("payload")
                if not isinstance(artifact, dict):
                    return {"command_id": command["command_id"], "disposition": "rejected_invalid", "reason": "calibration artifact payload required"}
                if command.get("artifact_digest") != artifact.get("artifact_digest"):
                    return {"command_id": command["command_id"], "disposition": "rejected_invalid", "reason": "command artifact digest differs from payload"}
                self.store.put_calibration_artifact(artifact)
                return {"command_id": command["command_id"], "disposition": "stored", "artifact_id": artifact.get("id"), "artifact_digest": artifact.get("artifact_digest"), "controller_generation": command.get("controller_generation")}
            if kind == "request_recovery_manifest":
                return {"command_id": command["command_id"], "disposition": "completed", "recovery_manifest": self.store.recovery_manifest()}
            if kind == "hardware_rescan":
                try:
                    observation = (self.hardware_service.discover() if self.hardware_service is not None
                                   else self.hardware_request({"operation": "discover"}, self.timeout))
                except HardwareUnavailableError as error:
                    # The service owns serial and classifies probe failures;
                    # retain that typed result at the command boundary too.
                    observation = {"source": "physical", "connection_state": "disconnected",
                                   "probe_outcome": error.outcome.value,
                                   "transport_evidence": dict(error.evidence),
                                   "physical_actuation": False}
                    self.store.record_hardware_observation(observation)
                    return {"command_id": command["command_id"], "disposition": "failed",
                            "reason": str(error), "probe_outcome": error.outcome.value,
                            "retryable": error.outcome.value == "timeout",
                            "hardware_observation": observation, "physical_actuation": False}
                except TimeoutError as error:
                    observation = {"source": "physical", "connection_state": "disconnected",
                                   "probe_outcome": "timeout", "transport_evidence": {"detail": str(error)[:256]},
                                   "physical_actuation": False}
                    self.store.record_hardware_observation(observation)
                    return {"command_id": command["command_id"], "disposition": "failed",
                            "reason": str(error), "probe_outcome": "timeout", "retryable": True,
                            "hardware_observation": observation, "physical_actuation": False}
                except (OSError, RuntimeError) as error:
                    return {"command_id": command["command_id"], "disposition": "failed",
                            "reason": str(error), "probe_outcome": "open", "retryable": True,
                            "physical_actuation": False}
                if not isinstance(observation, dict):
                    return {"command_id": command["command_id"], "disposition": "failed",
                            "reason": "hardware discovery returned an invalid observation",
                            "retryable": False, "physical_actuation": False}
                return {"command_id": command["command_id"], "disposition": "completed",
                        "hardware_observation": observation,
                        "device_identity": observation.get("device_identity"),
                        "identity_state": observation.get("identity_state"),
                        "physical_actuation": False}
            if kind == "emergency_safe_stop":
                if self.manual_executor is not None:
                    return self.manual_executor.execute(command)
                # This is an auditable local intent only.  The sync boundary
                # never pretends to have reached hardware; a hardware service
                # may execute it later under its own lease/generation checks.
                self.store.record_hardware_observation({"source": "central_intent", "connection_state": "degraded",
                    "component": "all_actuators", "component_state": "safe_stop_requested",
                    "command_id": command["command_id"], "controller_generation": command.get("controller_generation"),
                    "physical_actuation": False})
                return {"command_id": command["command_id"], "disposition": "safe_stop_intent_recorded",
                        "physical_actuation": False, "controller_generation": command.get("controller_generation")}
            if kind in {"stir_pulse", "heater_pulse"}:
                if self.manual_executor is None:
                    return {"command_id": command["command_id"], "disposition": "deferred_no_hardware_service",
                            "physical_actuation": False}
                return self.manual_executor.execute(command)
            return {"command_id": command["command_id"], "disposition": "rejected_invalid", "reason": f"unsupported command_kind {kind}"}
        # Manual execution owns the durable command transaction itself.  Do
        # not wrap it in the generic delivery transaction: nested execution
        # would look like an interrupted replay and prevent actuation.
        if kind in {"stir_pulse", "heater_pulse", "emergency_safe_stop"} and self.manual_executor is not None:
            if all(isinstance(command.get(key), str) for key in ("lease_token", "lease_holder", "lease_expires_at")):
                self.store.set_control_lease(lease_token=command["lease_token"], owner=command["lease_holder"],
                                             generation=int(command.get("controller_generation", 0)),
                                             expires_at=command["lease_expires_at"])
            return self.manual_executor.execute(command)
        try:
            return self.store.execute_command(command, execute)
        except StaleGenerationError:
            return {"command_id": command.get("command_id"), "disposition": "rejected_stale_generation"}
        except Exception as error:
            # A stale revision is a normal safe rejection, never an auto-rebase.
            return {"command_id": command.get("command_id"), "disposition": "rejected_stale_revision" if error.__class__.__name__ == "StaleRevisionError" else "failed", "reason": str(error)}

    def run_loop(self, *, interval: float = 10.0, maximum_backoff: float = 300.0,
                 stop: Callable[[], bool] = lambda: False, inventory: Callable[[], list[Json]] = lambda: []) -> None:
        """Sync until stopped, with bounded exponential retry and no busy loop."""
        delay = interval
        while not stop():
            try:
                self.sync_once(inventory=inventory())
                if self.store.binding():
                    self.wait_once(wait_seconds=min(25.0, max(0.0, interval)))
                delay = interval
                delay = interval
            except sqlite3.OperationalError as error:
                if not _is_locked_database(error):
                    raise
                delay = min(maximum_backoff, max(interval, delay * 2))
            except (OSError, URLError, TimeoutError, RuntimeError, StaleGenerationError):
                delay = min(maximum_backoff, max(interval, delay * 2))
            time.sleep(delay)
