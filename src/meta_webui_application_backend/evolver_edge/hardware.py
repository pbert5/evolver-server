"""Read-only min-eVOLVER discovery and telemetry service.

This is deliberately a *service* boundary rather than a convenience serial
client.  It is the only edge component allowed to open the serial device;
callers receive durable inventory observations and telemetry through
``EdgeStore``.  The initial protocol allow-list contains no output-changing
commands, including the OD LED command used by upstream commissioning.

The wire grammar follows the current ``pbert5/evolver_code`` min-eVOLVER
hardware protocol (audited at b31ef16).  It is kept local so a deployed
controller does not need a source checkout of that project.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import fcntl
import errno
import glob
import re
import time
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol
from enum import StrEnum
import string
from uuid import uuid4
from uuid import NAMESPACE_URL, uuid5

from .store import EdgeStore, EdgeStoreError, Json, LeaseValidationError


HANDSHAKE = "WHO_ARE_YOU_!"
DEVICE_PROTOCOL_VERSION = "evolver.device.v2"
VERIFICATION_STATES = frozenset({"supported", "protocol_verified", "electrically_verified", "physically_verified", "calibrated", "not_tested", "failed", "ambiguous"})
ACTUATOR_BOUNDS = {
    "od_led_level": (0, 255),
    "pump_duration_ms": (1, 1000),
    "stir_duration_ms": (1, 1000),
    "stir_level": (1, 250),
    "heater_duration_ms": (1, 250),
    "heater_level": (1, 64),
}
_READ_ONLY_COMMANDS = ("HW_STATUS_!", "HW_READ_THERMISTOR,0_!", "HW_READ_THERMISTOR,1_!",
                       "HW_READ_PHOTODIODE,0_!", "HW_READ_PHOTODIODE,1_!")


class HardwareUnavailableError(EdgeStoreError):
    """The physical adapter is unavailable or another service owns serial."""

    outcome: "ProbeOutcome" = None  # type: ignore[assignment]
    evidence: Mapping[str, Any] = {}

    def __init__(self, message: str, *, outcome: "ProbeOutcome | None" = None,
                 evidence: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.outcome = outcome or ProbeOutcome.OPEN
        self.evidence = _bounded_evidence(evidence or {"detail": message})


class ProbeOutcome(StrEnum):
    """Finite, safe-to-project hardware probe outcomes."""

    OPEN = "open"
    PERMISSION = "permission"
    BUSY = "busy"
    TIMEOUT = "timeout"
    PROTOCOL = "protocol"
    MALFORMED = "malformed"
    STATUS = "status"
    IDENTITY = "identity"


def _bounded_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Keep diagnostics useful without persisting arbitrary wire/error data."""
    result: dict[str, Any] = {}
    for key, value in list(evidence.items())[:8]:
        safe_key = str(key)[:48]
        if isinstance(value, str):
            result[safe_key] = value[:256]
        elif isinstance(value, (int, float, bool)) or value is None:
            result[safe_key] = value
        else:
            result[safe_key] = str(value)[:256]
    return result


class ProbeError(HardwareUnavailableError):
    """A classified probe failure with bounded diagnostic evidence."""

    def __init__(self, outcome: ProbeOutcome, message: str,
                 *, evidence: Mapping[str, Any] | None = None,
                 cause: BaseException | None = None) -> None:
        super().__init__(message, outcome=outcome,
                         evidence={"outcome": outcome.value, **(evidence or {})})
        if cause is not None:
            self.__cause__ = cause


def _transport_error(error: BaseException, *, operation: str) -> ProbeError:
    number = getattr(error, "errno", None)
    text = str(error)[:256]
    if isinstance(error, TimeoutError) or number == errno.ETIMEDOUT or "timeout" in text.lower():
        outcome = ProbeOutcome.TIMEOUT
    elif number in {errno.EACCES, errno.EPERM} or "permission denied" in text.lower():
        outcome = ProbeOutcome.PERMISSION
    elif number == errno.EBUSY or "resource busy" in text.lower() or "device or resource busy" in text.lower():
        outcome = ProbeOutcome.BUSY
    else:
        outcome = ProbeOutcome.OPEN if operation == "open" else ProbeOutcome.PROTOCOL
    return ProbeError(outcome, f"{operation} failed: {text}",
                      evidence={"operation": operation, "errno": number, "detail": text}, cause=error)


class ReadOnlyTransport(Protocol):
    """Minimal transport injected by the dedicated hardware service."""

    port: str

    def open(self) -> None: ...
    def close(self) -> None: ...
    def exchange(self, payload: str) -> str: ...


class LocalSerialTransport:
    """pyserial transport; import pyserial only on actual physical use."""

    def __init__(self, port: str, *, baudrate: int = 9600, timeout: float = 2.0) -> None:
        self.port, self.baudrate, self.timeout = port, baudrate, timeout
        self._serial: object | None = None

    def open(self) -> None:
        try:
            import serial  # type: ignore[import-not-found]
            self._serial = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
            # A reopened CDC ACM endpoint can retain bytes from the previous
            # owner/session.  They are never valid responses to this session's
            # first command, so establish the session boundary before writing.
            self._serial.reset_input_buffer()  # type: ignore[union-attr]
        except ImportError as error:
            raise ProbeError(ProbeOutcome.OPEN, "pyserial is required for physical eVOLVER discovery", cause=error)
        except Exception as error:
            raise _transport_error(error, operation="open") from error

    def close(self) -> None:
        if self._serial is not None:
            self._serial.close()  # type: ignore[union-attr]
            self._serial = None

    def usb_hardware_fingerprint(self) -> dict[str, Any]:
        """Read complete USB metadata for this endpoint; never use tty names."""
        try:
            from serial.tools import list_ports  # type: ignore[import-not-found]
            from .identity import samd21_hardware_fingerprint
            endpoint = str(Path(self.port).resolve())
            matches = [info for info in list_ports.comports(include_links=False)
                       if str(Path(info.device).resolve()) == endpoint]
            if len(matches) != 1:
                raise ProbeError(ProbeOutcome.IDENTITY, "USB endpoint metadata is missing or ambiguous")
            info = matches[0]
            if info.vid is None or info.pid is None or not info.serial_number:
                raise ProbeError(ProbeOutcome.IDENTITY, "USB VID/PID/serial metadata is incomplete")
            return samd21_hardware_fingerprint(vid=info.vid, pid=info.pid,
                                               usb_serial=info.serial_number,
                                               manufacturer=info.manufacturer,
                                               product=info.product)
        except ProbeError:
            raise
        except Exception as error:
            raise ProbeError(ProbeOutcome.IDENTITY, "USB metadata lookup failed", cause=error) from error

    def exchange(self, payload: str) -> str:
        if self._serial is None:
            raise ProbeError(ProbeOutcome.OPEN, "serial device is not open")
        try:
            # MEV frames are terminated by !.  Do not add a line terminator:
            # it becomes an extra command byte on firmware that consumes exact
            # frames.
            self._serial.write(payload.encode())  # type: ignore[union-attr]
            self._serial.flush()  # type: ignore[union-attr]
            # The firmware terminates replies with Serial.println(); only
            # requests use the ! command terminator.
            deadline = time.monotonic() + self.timeout
            while True:
                raw = self._serial.read_until(b"\n")  # type: ignore[union-attr]
                # The SAMD21 application can expose the checksum marker of
                # the preceding exact-frame request at the next read boundary.
                # It is stale transport data, never a valid STATUS/WHO reply;
                # discard only the two known cross-frame forms and retain the
                # original bounded deadline.
                text = raw.rstrip(b"\r\n").decode(errors="replace")
                wants_status = payload.startswith("HW_")
                stale = ((wants_status and text.startswith("WHO_ARE_YOU|")) or
                         (not wants_status and text.startswith("HW|")))
                if not stale or time.monotonic() >= deadline:
                    break
                self._serial.timeout = max(0.0, deadline - time.monotonic())  # type: ignore[union-attr]
        except Exception as error:
            raise _transport_error(error, operation="exchange") from error
        if not raw:
            raise ProbeError(ProbeOutcome.TIMEOUT, f"timeout waiting for {payload}",
                             evidence={"operation": "exchange", "command": payload})
        if not raw.endswith(b"\n"):
            raise ProbeError(ProbeOutcome.TIMEOUT, f"incomplete frame waiting for {payload}",
                             evidence={"operation": "exchange", "command": payload,
                                       "bytes_received": len(raw)})
        return raw.rstrip(b"\r\n").decode(errors="replace")


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    firmware: str
    hw_protocol: int
    raw: str
    identity_state: str = "valid"
    owner_id: str | None = None

    @property
    def provisioned(self) -> bool:
        return self.identity_state == IdentityState.VALID


class IdentityState(StrEnum):
    """The only safe interpretations of the firmware identity field."""

    UNPROVISIONED = "unprovisioned"
    VALID = "valid"
    INVALID = "invalid"


def normalize_identity(value: object) -> tuple[IdentityState, str | None]:
    """Classify the firmware field without turning arbitrary corruption into blank.

    The vendored firmware emits the exact uppercase sentinel ``BLANK`` when
    its persistent identity magic/ID is absent.  It accepts 1..31 characters
    excluding comma, newline, ``_!``; the host additionally rejects frame
    separators and non-printable values because those cannot be represented
    unambiguously in a MEV frame.
    """
    if value is None:
        return IdentityState.UNPROVISIONED, None
    if not isinstance(value, str):
        return IdentityState.INVALID, None
    candidate = value.strip()
    if candidate == "" or candidate == "BLANK":
        return IdentityState.UNPROVISIONED, None
    if not 1 <= len(candidate) <= 31 or any(
        char not in string.printable or char in "|,\r\n_!" for char in candidate
    ):
        return IdentityState.INVALID, candidate
    return IdentityState.VALID, candidate


@dataclass(frozen=True)
class HardwareCommand:
    """Typed local request; this is not a wire frame or a physical event."""
    operation: str
    command_id: str
    target_identity: str
    parameters: Mapping[str, Any]
    timeout: float = 2.0
    requested_at: str = ""
    controller_id: str | None = None
    run_id: str | None = None
    controller_generation: int = 0
    lease_token: str | None = None
    lease_owner: str | None = None
    require_lease: bool = False
    operator: str | None = None
    schema_version: str = DEVICE_PROTOCOL_VERSION


@dataclass(frozen=True)
class HardwareResult:
    command_id: str
    request_accepted: bool
    protocol_response: str
    observed_evidence: Mapping[str, Any]
    verification: str
    retryable: bool

    def as_json(self) -> dict[str, Any]:
        return {"command_id": self.command_id, "request_accepted": self.request_accepted,
                "protocol_response": self.protocol_response, "observed_evidence": dict(self.observed_evidence),
                "verification": self.verification, "retryable": self.retryable}


def discover_ports(port: str | None = None) -> list[str]:
    """Only enumerate candidates; identity comes from the device handshake."""
    return [port] if port else sorted(glob.glob("/dev/ttyACM*"))


def parse_identity(reply: str) -> DeviceIdentity:
    """Reject unrelated USB ACM devices and unsupported min-eVOLVER replies."""
    raw = reply.strip()
    fields = raw.split("|")
    if len(fields) < 6 or fields[0] != "MEV":
        raise ProbeError(ProbeOutcome.MALFORMED, "response is not a min-eVOLVER identity reply",
                         evidence={"operation": "identity", "reply": raw})
    try:
        if int(fields[1]) != 2:
            raise ProbeError(ProbeOutcome.PROTOCOL, f"unsupported min-eVOLVER protocol {fields[1]!r}",
                             evidence={"operation": "identity", "protocol": fields[1]})
    except ValueError as error:
        raise ProbeError(ProbeOutcome.MALFORMED, "invalid min-eVOLVER protocol version",
                         evidence={"operation": "identity", "protocol": fields[1]}, cause=error)
    metadata = dict(item.split("=", 1) for item in fields[5].split(",") if "=" in item)
    if metadata.get("type") != "minievolver":
        raise ProbeError(ProbeOutcome.IDENTITY, "identity reply is not from a min-eVOLVER",
                         evidence={"operation": "identity", "type": metadata.get("type")})
    try:
        hw_protocol = int(metadata.get("hw_proto", "0"))
    except ValueError as error:
        raise ProbeError(ProbeOutcome.MALFORMED, "invalid min-eVOLVER hardware protocol version",
                         evidence={"operation": "identity", "hw_proto": metadata.get("hw_proto")}, cause=error)
    if hw_protocol < 1:
        raise ProbeError(ProbeOutcome.PROTOCOL, "min-eVOLVER does not support the read-only hardware protocol",
                         evidence={"operation": "identity", "hw_proto": hw_protocol})
    raw_identity = metadata.get("id", fields[2])
    identity_state, device_id = normalize_identity(raw_identity)
    if identity_state is IdentityState.INVALID:
        # Keep the observation available to the caller, but never let it take
        # the unprovisioned path or derive a durable instrument identity.
        device_id = str(raw_identity).strip()
    owner = metadata.get("owner")
    return DeviceIdentity(device_id or "", metadata.get("fw", "unknown"), hw_protocol, raw,
                          identity_state.value, owner.strip() if isinstance(owner, str) else None)


def _reply(reply: str, expected: str) -> dict[str, str]:
    parts = reply.strip().split("|")
    if len(parts) < 4 or parts[0] != "HW" or parts[2] != "OK":
        raise ProbeError(ProbeOutcome.MALFORMED, f"invalid reply for {expected}",
                         evidence={"operation": expected.lower(), "reply": reply})
    if parts[3] != expected:
        raise ProbeError(ProbeOutcome.STATUS if expected == "STATUS" else ProbeOutcome.PROTOCOL,
                         f"unexpected reply for {expected}: {parts[3]!r}",
                         evidence={"operation": expected.lower(), "reply_type": parts[3]})
    try:
        if int(parts[1]) < 1:
            raise ProbeError(ProbeOutcome.PROTOCOL, "unsupported hardware reply version",
                             evidence={"operation": expected.lower(), "version": parts[1]})
    except ValueError as error:
        raise ProbeError(ProbeOutcome.MALFORMED, "invalid hardware reply version",
                         evidence={"operation": expected.lower(), "version": parts[1]}, cause=error)
    return dict(item.split("=", 1) for item in parts[4].split(",") if "=" in item) if len(parts) > 4 else {}


def _identity_reply(reply: str) -> DeviceIdentity:
    return parse_identity(reply)


def _reported_state(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if value in {"on", "active", "enabled", "running", "1", "true"}:
        return "active"
    if value in {"off", "inactive", "disabled", "idle", "0", "false"}:
        return "inactive"
    if value in {"unknown", "unavailable", "not_reported"}:
        return "unavailable" if value == "unavailable" else "unknown"
    if value in {"fault", "failed", "error"}:
        return "fault"
    return None


def normalize_effective_device_state(status: Mapping[str, str]) -> Json:
    """Expose actuator-effective state only when the device reports it.

    The current firmware reports aggregate temperature control but does not
    report pump/stir pulse state.  Those fields therefore remain explicitly
    unknown; an ACK or an absent field is never upgraded into physical
    evidence.  Newer firmware may report ``pump_state``/``stir_state`` or
    per-channel ``pump_<n>``/``stir_<n>`` fields without changing this shape.
    """
    def state_for(name: str) -> Json:
        value = status.get(f"{name}_state", status.get(name))
        state = _reported_state(value)
        channels = {key: _reported_state(value) for key, value in status.items()
                    if re.fullmatch(rf"{re.escape(name)}_\d+", key)}
        channels = {key: value for key, value in channels.items() if value is not None}
        if channels:
            distinct = set(channels.values())
            return {"effective_state": next(iter(distinct)) if len(distinct) == 1 else "mixed",
                    "channels": channels, "evidence": "protocol_verified"}
        if state is None:
            return {"effective_state": "unknown", "evidence": "not_reported"}
        return {"effective_state": state, "evidence": "protocol_verified"}

    temperature = state_for("temperature")
    if "temp_control" in status:
        reported = _reported_state(status["temp_control"])
        if reported is not None:
            temperature = {"effective_state": reported, "evidence": "protocol_verified"}
    return {"pump": state_for("pump"), "stir": state_for("stir"), "temperature": temperature}


def _bounded(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    low, high = ACTUATOR_BOUNDS[name]
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


class ReadOnlyHardwareService:
    """One-owner physical discovery/read service with a process-wide lock.

    A systemd hardware service should retain this instance and expose its
    observations to the controller; the lock also prevents a diagnostics CLI
    or a second controller process from racing it for the serial port.
    """

    def __init__(self, store: EdgeStore, transport: ReadOnlyTransport, *, startup_attempts: int = 3) -> None:
        if startup_attempts < 1 or startup_attempts > 5:
            raise ValueError("startup_attempts must be between 1 and 5")
        self.store, self.transport = store, transport
        self.startup_attempts = startup_attempts
        self._lock_path = store.root / "hardware-service.lock"

    @contextmanager
    def _session(self) -> Iterator[None]:
        self._lock_path.touch(mode=0o600, exist_ok=True)
        with self._lock_path.open("r+") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ProbeError(ProbeOutcome.BUSY, "another eVOLVER hardware service owns serial",
                                 evidence={"operation": "lock"}, cause=error)
            try:
                self.transport.open()
                yield
            finally:
                try:
                    self.transport.close()
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _identity_with_startup_retry(self) -> DeviceIdentity:
        """Read identity with a bounded, immediate retry for USB reset startup.

        Opening a CDC ACM device can reset the board.  The serial transport's
        bounded read timeout is the readiness gate; retrying only timeout
        outcomes avoids sleeps and never sends anything except the handshake.
        Some transports report that timeout as an empty successful read rather
        than raising ``ProbeError``; normalize that representation here so it
        follows the same bounded startup path.
        """
        last: ProbeError | None = None
        for attempt in range(1, self.startup_attempts + 1):
            try:
                reply = self.transport.exchange(HANDSHAKE)
                if reply is None or (isinstance(reply, str) and not reply.strip()):
                    raise ProbeError(ProbeOutcome.TIMEOUT, "no identity bytes received",
                                     evidence={"operation": "identity", "empty_reply": True})
                return parse_identity(reply)
            except ProbeError as error:
                last = ProbeError(error.outcome, str(error),
                                  evidence={**error.evidence, "attempt": attempt,
                                            "max_attempts": self.startup_attempts})
                if error.outcome is not ProbeOutcome.TIMEOUT:
                    raise last from error
        assert last is not None
        raise last

    def discover(self) -> Json:
        """Discover a physical device without sending any actuator command.

        An unprovisioned device is returned for operator visibility but is not
        registered as an instrument: assigning a durable identity from a tty
        path would make reconnect/replacement unsafe.
        """
        with self._session():
            identity = self._identity_with_startup_retry()
            status = _reply(self.transport.exchange("HW_STATUS_!"), "STATUS")
            fingerprint = (self.transport.usb_hardware_fingerprint()
                           if isinstance(self.transport, LocalSerialTransport) else None)
        observation: Json = {"source": "physical", "connection_state": "connected",
                             "transport": {"kind": "usb_serial", "path": self.transport.port},
                             "firmware": identity.firmware, "hardware_protocol": identity.hw_protocol,
                             "device_identity": identity.device_id or None,
                             "identity_state": "provisioned" if identity.provisioned else identity.identity_state,
                             "status": status,
                             "effective_device_state": normalize_effective_device_state(status),
                             "transport_evidence": {"event": "connected", "rescan": True},
                             "hardware_fingerprint": fingerprint}
        if not identity.provisioned:
            self.store.record_hardware_observation({**observation, "identity_ambiguous": identity.identity_state == "invalid"})
            return observation
        instrument_id = str(uuid5(NAMESPACE_URL, f"minievolver/{identity.device_id}"))
        sleeves = _nonnegative_int(status.get("sleeves"), default=2)
        observation.update({"id": instrument_id, "controller_id": self.store.identity()["id"],
                            "instrument_type": "minievolver", "capabilities": _capabilities(),
                            "vial_positions": [{"id": str(uuid5(NAMESPACE_URL, f"{instrument_id}/vial/{index}")),
                                                "instrument_id": instrument_id, "position_index": index}
                                               for index in range(sleeves)]})
        self.store.register_instruments([observation])
        self.store.record_hardware_observation({"source": "physical", "connection_state": "connected",
                                                "transport": observation["transport"], "device_identity": identity.device_id,
                                                "identity_state": "provisioned", "instrument_id": instrument_id,
                                                "transport_evidence": {"event": "connected", "rescan": True}})
        return self.store.instrument(instrument_id)

    def capture_telemetry(self, instrument_id: str) -> Json:
        """Capture raw safe sensor readings into the normal edge telemetry spool."""
        instrument = self.store.instrument(instrument_id)
        if instrument.get("instrument_type") != "minievolver":
            raise HardwareUnavailableError("read-only hardware service only serves min-eVOLVER instruments")
        with self._session():
            identity = self._identity_with_startup_retry()
            if not identity.provisioned or str(uuid5(NAMESPACE_URL, f"minievolver/{identity.device_id}")) != instrument_id:
                raise ProbeError(ProbeOutcome.IDENTITY, "attached device does not match the registered instrument",
                                 evidence={"operation": "telemetry", "instrument_id": instrument_id,
                                           "device_identity": identity.device_id or None})
            values: dict[str, int] = {}
            for channel in range(len(instrument["vial_positions"])):
                try:
                    values[f"thermistor_adc_{channel}"] = int(_reply(self.transport.exchange(f"HW_READ_THERMISTOR,{channel}_!"), "THERMISTOR")["value"])
                    values[f"photodiode_adc_{channel}"] = int(_reply(self.transport.exchange(f"HW_READ_PHOTODIODE,{channel}_!"), "PHOTODIODE")["value"])
                except (KeyError, TypeError, ValueError) as error:
                    raise ProbeError(ProbeOutcome.MALFORMED, "sensor value is malformed",
                                     evidence={"operation": "telemetry", "channel": channel}, cause=error) from error
        stream_id = f"instrument:{instrument_id}:read_only_sensors"
        previous = self.store.telemetry_after(stream_id)
        record = self.store.spool_telemetry(stream_id=stream_id, sequence=(previous[-1]["sequence"] + 1 if previous else 1),
                                          payload={**values, "instrument_id": instrument_id,
                                                   "vial_position_ids": [item["id"] for item in instrument["vial_positions"]],
                                                   "source": "physical", "read_only": True,
                                                   "calibration": {"temperature": "not_calibrated", "od": "not_calibrated"}},
                                           captured_at=datetime.now(UTC).isoformat())
        self.store.record_instrument_transport(instrument_id, connection_state="connected",
                                               transport={"kind": "usb_serial", "path": self.transport.port},
                                               reason="sensor_observation")
        return record


class HardwareService(ReadOnlyHardwareService):
    """Exclusive serial owner for the audited MEV hardware maintenance API.

    ``allow_physical`` is intentionally false by default.  Protocol commands
    can be exercised with a mock transport, while actuator frames require both
    this gate and an operator attribution.  Firmware ACKs are never physical
    verification.
    """

    def __init__(self, store: EdgeStore, transport: ReadOnlyTransport, *, allow_physical: bool = False,
                 operator: str | None = None, daemon_capable: bool = False,
                 startup_attempts: int = 3) -> None:
        super().__init__(store, transport, startup_attempts=startup_attempts)
        self.allow_physical, self.operator, self.daemon_capable = allow_physical, operator, daemon_capable

    def _require_target(self, target_identity: str) -> DeviceIdentity:
        with self._session():
            identity = _identity_reply(self.transport.exchange(HANDSHAKE))
        if not identity.provisioned or identity.device_id != target_identity:
            raise HardwareUnavailableError("attached device identity does not match command target")
        return identity

    def _execute(self, request: HardwareCommand, frame: str, expected: str, *, actuator: bool = False,
                 retryable: bool = True) -> HardwareResult:
        if request.operation not in {"get_status", "read_sensor", "safe_stop", "set_output", "pulse_pump", "set_stir", "pulse_heater"}:
            raise ValueError(f"unsupported hardware operation {request.operation}")
        effective_operator = request.operator or self.operator
        if actuator and (not (self.allow_physical or self.daemon_capable) or not effective_operator):
            raise PermissionError("physical actuation requires --physical and operator attribution")
        # Direct mock/developer service calls retain the historical physical
        # gate when no lease has ever been installed; once a lease exists, or
        # for every daemon IPC request, lease fencing is mandatory.
        if actuator and (request.require_lease or self.store.meta("control_lease") is not None):
            self.store.validate_control_lease(lease_token=request.lease_token, owner=request.lease_owner or effective_operator,
                                              generation=request.controller_generation)
        if request.timeout <= 0:
            raise ValueError("timeout must be positive")
        def handler() -> dict[str, Any]:
            try:
                with self._session():
                    identity = _identity_reply(self.transport.exchange(HANDSHAKE))
                    if not identity.provisioned or identity.device_id != request.target_identity:
                        raise HardwareUnavailableError("attached device identity does not match command target")
                    raw = self.transport.exchange(frame)
                fields = _reply(raw, expected)
                return HardwareResult(request.command_id, True, raw, {**fields, "operator": effective_operator} if actuator else fields,
                                      "protocol_verified", retryable).as_json()
            except (HardwareUnavailableError, ValueError) as error:
                if not actuator:
                    raise
                component = "pump" if request.operation == "pulse_pump" else request.operation
                self.store.record_hardware_observation({"source": "physical", "connection_state": "degraded",
                    "component": component, "component_state": "fault", "fault": {"kind": "actuator_protocol", "reason": str(error)},
                    "command_id": request.command_id, "controller_generation": request.controller_generation})
                return HardwareResult(request.command_id, False, str(error),
                                      {"component": component, "fault": str(error), "operator": self.operator},
                                      "protocol_failed", False).as_json()
        result = self.store.execute_command({"command_id": request.command_id,
                                              "controller_generation": request.controller_generation}, handler)
        return HardwareResult(result["command_id"], result["request_accepted"], result["protocol_response"],
                              result["observed_evidence"], result["verification"], result["retryable"])

    def request(self, request: HardwareCommand) -> HardwareResult:
        if not request.command_id or not request.target_identity:
            raise ValueError("hardware command requires command_id and target_identity")
        validate_device_operation(request.operation, request.parameters)
        p = request.parameters
        if request.operation == "get_status":
            return self._execute(request, "HW_STATUS_!", "STATUS")
        if request.operation == "safe_stop":
            return self._execute(request, "HW_SAFE_!", "SAFE", actuator=True, retryable=True)
        channel = p.get("channel")
        if not isinstance(channel, int) or channel < 0:
            raise ValueError("channel must be a non-negative integer")
        if request.operation == "read_sensor":
            kind = p.get("sensor")
            if kind not in {"temperature", "od"}:
                raise ValueError("sensor must be temperature or od")
            return self._execute(request, f"HW_READ_{'THERMISTOR' if kind == 'temperature' else 'PHOTODIODE'},{channel}_!",
                                 "THERMISTOR" if kind == "temperature" else "PHOTODIODE")
        if request.operation == "set_output":
            if p.get("output") != "od_led": raise ValueError("only od_led output is supported")
            level = _bounded("od_led_level", p.get("level"))
            return self._execute(request, f"HW_SET_OD_LED,{channel},{level}_!", "SET_OD_LED", actuator=True)
        if request.operation == "pulse_pump":
            duration = _bounded("pump_duration_ms", p.get("duration_ms"))
            return self._execute(request, f"HW_PULSE_PUMP,{channel},{duration}_!", "PULSE_PUMP", actuator=True, retryable=False)
        if request.operation == "set_stir":
            duration, level = _bounded("stir_duration_ms", p.get("duration_ms")), _bounded("stir_level", p.get("level"))
            return self._execute(request, f"HW_PULSE_STIR,{channel},{duration},{level}_!", "PULSE_STIR", actuator=True, retryable=False)
        if request.operation == "pulse_heater":
            duration, level = _bounded("heater_duration_ms", p.get("duration_ms")), _bounded("heater_level", p.get("level"))
            return self._execute(request, f"HW_PULSE_HEATER,{channel},{duration},{level}_!", "PULSE_HEATER", actuator=True, retryable=False)
        raise ValueError(f"unsupported hardware operation {request.operation}")

    def command(self, operation: str, target_identity: str, parameters: Mapping[str, Any], **context: Any) -> HardwareResult:
        if "controller_generation" not in context:
            binding = self.store.binding()
            # Diagnostics are commands too: when a binding exists they must
            # carry its current generation so the store can fence them. An
            # explicit generation is left untouched for normal stale checks.
            context["controller_generation"] = binding.get("generation", 0) if isinstance(binding, dict) else 0
            if operation in {"safe_stop", "set_output", "pulse_pump", "set_stir", "pulse_heater"}:
                if (self.allow_physical or self.daemon_capable) and self.operator and (
                        not isinstance(binding, dict) or not isinstance(binding.get("generation"), int) or binding["generation"] <= 0):
                    raise EdgeStoreError("physical actuation requires an active positive controller generation")
        return self.request(HardwareCommand(operation=operation, command_id=context.pop("command_id", str(uuid4())),
                                             target_identity=target_identity, parameters=parameters,
                                             requested_at=context.pop("requested_at", datetime.now(UTC).isoformat()),
                                             lease_token=context.pop("lease_token", None), lease_owner=context.pop("lease_owner", None),
                                             operator=context.pop("operator", None), **context))

    def provision_identity(self, *, device_id: str, owner_id: str, operator: str,
                           command_id: str | None = None) -> HardwareResult:
        if not self.allow_physical or not operator: raise PermissionError("identity provisioning requires physical authorization")
        if not (1 <= len(device_id) <= 31 and 1 <= len(owner_id) <= 31) or any(c in device_id + owner_id for c in ",\r\n_!"):
            raise ValueError("identity values must be 1..31 characters and contain no protocol delimiters")
        identity_state, normalized_device_id = normalize_identity(device_id)
        if identity_state is not IdentityState.VALID or normalized_device_id != device_id:
            raise ValueError("device_id must be a protocol-safe valid identity")
        binding = self.store.binding()
        generation = int(binding.get("generation", 0)) if isinstance(binding, dict) else 0
        request = HardwareCommand("provision_identity", command_id or str(uuid4()), "BLANK", {"device_id": device_id, "owner_id": owner_id}, controller_generation=generation)
        def handler() -> dict[str, Any]:
            with self._session():
                current = _identity_reply(self.transport.exchange(HANDSHAKE))
                if current.identity_state != IdentityState.UNPROVISIONED:
                    if current.provisioned:
                        raise HardwareUnavailableError("device already provisioned; explicit clear is required")
                    raise HardwareUnavailableError("device identity is invalid or ambiguous; operator reconciliation is required")
                try:
                    raw = self.transport.exchange(f"PROVISION,{device_id},{owner_id}_!")
                except HardwareUnavailableError as error:
                    if error.outcome is not ProbeOutcome.TIMEOUT:
                        raise
                    # The write may have reached the device even when its ACK
                    # timed out. Reconcile once; never resend a provisioning
                    # frame whose physical effect is unknown.
                    try:
                        verified = _identity_reply(self.transport.exchange(HANDSHAKE))
                    except (HardwareUnavailableError, ProbeError) as readback_error:
                        raise HardwareUnavailableError(
                            "identity provisioning timed out; read-back unavailable; no automatic retry",
                            outcome=ProbeOutcome.TIMEOUT,
                            evidence={"operation": "provision", "readback": "unavailable"},
                        ) from readback_error
                    if verified.identity_state != IdentityState.VALID or verified.device_id != device_id or verified.owner_id != owner_id:
                        raise HardwareUnavailableError(
                            "identity provisioning timed out; read-back mismatch; no automatic retry",
                            outcome=ProbeOutcome.IDENTITY,
                            evidence={"operation": "provision", "readback": "mismatch"},
                        )
                    raw = "PROVISION_TIMEOUT_READBACK"
                if raw != "PROVISION_TIMEOUT_READBACK" and "|PROVISION_ACK|" not in raw:
                    raise HardwareUnavailableError(f"identity provisioning failed: {raw}")
                if raw != "PROVISION_TIMEOUT_READBACK":
                    verified = _identity_reply(self.transport.exchange(HANDSHAKE))
                if verified.identity_state != IdentityState.VALID or verified.device_id != device_id:
                    raise HardwareUnavailableError("identity read-back mismatch; state is ambiguous")
                if verified.owner_id != owner_id:
                    raise HardwareUnavailableError("owner read-back mismatch; state is ambiguous")
            return HardwareResult(request.command_id, True, raw, {"device_id": verified.device_id, "owner_id": owner_id, "operator": operator}, "protocol_verified", False).as_json()
        result = self.store.execute_command({"command_id": request.command_id,
                                              "controller_generation": request.controller_generation,
                                              "requested_device": device_id,
                                              "requested_owner": owner_id,
                                              "operator": operator}, handler)
        return HardwareResult(result["command_id"], result["request_accepted"], result["protocol_response"], result["observed_evidence"], result["verification"], result["retryable"])

    def clear_identity(self, *, target_identity: str, operator: str, confirm: bool = False) -> HardwareResult:
        """Explicit destructive maintenance; never reachable by normal discovery."""
        if not self.allow_physical or not operator or not confirm:
            raise PermissionError("clearing identity requires physical mode, operator, and explicit confirmation")
        request = HardwareCommand("clear_identity", str(uuid4()), target_identity, {}, requested_at=datetime.now(UTC).isoformat())
        def handler() -> dict[str, Any]:
            with self._session():
                identity = _identity_reply(self.transport.exchange(HANDSHAKE))
                if identity.device_id != target_identity: raise HardwareUnavailableError("identity target mismatch")
                raw = self.transport.exchange("CLEAR_ID_!")
                if "CLEAR_ACK" not in raw: raise HardwareUnavailableError(f"identity clear failed: {raw}")
                if _identity_reply(self.transport.exchange(HANDSHAKE)).provisioned: raise HardwareUnavailableError("identity clear read-back failed")
            return HardwareResult(request.command_id, True, raw, {"identity_cleared": True, "operator": operator}, "protocol_verified", False).as_json()
        result = self.store.execute_command({"command_id": request.command_id, "controller_generation": 0}, handler)
        return HardwareResult(result["command_id"], result["request_accepted"], result["protocol_response"], result["observed_evidence"], result["verification"], result["retryable"])


def _nonnegative_int(value: str | None, *, default: int) -> int:
    try:
        return max(0, int(value)) if value is not None else default
    except ValueError:
        return default


def _capabilities() -> Json:
    # The firmware protocol supports these operations, but no physical
    # actuation was performed during repository validation.  ``enabled``
    # therefore remains false until an operator supplies physical evidence.
    return {"device_protocol_version": DEVICE_PROTOCOL_VERSION,
            "firmware_hardware_protocol": 1,
            "od_read": {"verification": "protocol_verified", "calibration": "not_calibrated"},
            "temperature_read": {"verification": "protocol_verified", "calibration": "not_calibrated"},
            "pump_control": {"verification": "not_tested", "enabled": False, "supported": True,
                             "channels": 6, "mode": "timed_pulse", "direction": "forward",
                             "duration_ms": {"minimum": 1, "maximum": 1000}, "volume": {"supported": False}},
            "stir_control": {"verification": "not_tested", "enabled": False, "supported": True,
                             "channels": 2, "mode": "pwm_pulse", "level": {"minimum": 1, "maximum": 250},
                             "duration_ms": {"minimum": 1, "maximum": 1000}},
            "heater_control": {"verification": "not_tested", "enabled": False, "supported": True,
                               "mode": "output_pulse", "temperature_setpoint": {"supported": False, "reason": "firmware commissioning protocol exposes heater output, not a target"}},
            "temperature_setpoint": {"supported": False, "reason": "firmware does not expose a temperature-setpoint operation"},
            "safe_stop": {"supported": True, "enabled": False, "scope": "all_outputs"}}


def validate_device_operation(operation: str, parameters: Mapping[str, Any]) -> None:
    """Reject unsupported actuator semantics before identity/serial I/O."""
    if operation not in {"get_status", "read_sensor", "safe_stop", "set_output", "pulse_pump", "set_stir", "pulse_heater"}:
        raise ValueError(f"unsupported device operation {operation}")
    if operation == "pulse_pump" and parameters.get("direction", "forward") != "forward":
        raise ValueError("reverse pumping is unsupported by verified firmware")
    if operation in {"read_sensor", "set_output", "pulse_pump", "pulse_heater"}:
        channel = parameters.get("channel")
        if isinstance(channel, bool) or not isinstance(channel, int):
            raise ValueError("channel must be an integer")
        high = 5 if operation == "pulse_pump" else 1
        if not 0 <= channel <= high:
            raise ValueError(f"channel must be between 0 and {high}")
    if operation == "set_stir":
        channel = parameters.get("channel")
        if isinstance(channel, bool) or not isinstance(channel, int) or not 0 <= channel <= 1:
            raise ValueError("stir channel must be between 0 and 1")
