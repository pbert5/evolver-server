"""Bounded local API for the single eVOLVER hardware daemon.

The socket carries typed JSON requests only.  It is deliberately not a serial
proxy: frame construction, identity fencing, lease checks, and idempotency
remain in :mod:`hardware` and :class:`EdgeStore`.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from .hardware import HardwareService
from .store import EdgeStore, EdgeStoreError

MAX_MESSAGE = 16 * 1024
DEFAULT_SOCKET = "/run/evolver-controller/hardware.sock"
DEFAULT_IPC_TIMEOUT_SECONDS = 5.0
HARDWARE_EXCHANGE_TIMEOUT_SECONDS = 2.0
PROVISIONING_EXCHANGE_COUNT = 3
PROVISIONING_INNER_BUDGET_SECONDS = PROVISIONING_EXCHANGE_COUNT * HARDWARE_EXCHANGE_TIMEOUT_SECONDS
PROVISIONING_IPC_TIMEOUT_SECONDS = PROVISIONING_INNER_BUDGET_SECONDS + 1.0
READ_OPERATIONS = {"discover", "get_status", "read_sensor", "protocol_test"}
ACTUATOR_OPERATIONS = {"safe_stop", "set_stir", "set_output", "pulse_pump", "pulse_heater"}


def _send(sock: socket.socket, value: dict[str, Any]) -> None:
    data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_MESSAGE:
        raise ValueError("hardware IPC response is too large")
    sock.sendall(data)


def _recv(sock: socket.socket) -> dict[str, Any]:
    data = bytearray()
    while len(data) <= MAX_MESSAGE:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_MESSAGE or b"\n" not in data:
        raise ValueError("malformed or oversized hardware IPC request")
    try:
        value = json.loads(bytes(data).split(b"\n", 1)[0])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("malformed hardware IPC JSON") from error
    if not isinstance(value, dict):
        raise ValueError("hardware IPC request must be an object")
    return value


def _protocol_test(service: HardwareService) -> dict[str, Any]:
    found = service.discover()
    target = found.get("device_identity")
    if not target:
        raise EdgeStoreError("device is unprovisioned")
    results = [service.command("get_status", target, {})]
    for sensor in ("temperature", "od"):
        for channel in range(len(found.get("vial_positions", []))):
            results.append(service.command("read_sensor", target, {"sensor": sensor, "channel": channel}))
    return {"verification": "protocol_verified", "results": [item.as_json() for item in results]}


class HardwareIPCServer:
    def __init__(self, store: EdgeStore, service: HardwareService, path: str | Path = DEFAULT_SOCKET) -> None:
        self.store, self.service, self.path = store, service, Path(path)
        self._server: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(str(self.path))
        os.chmod(self.path, 0o660)
        self._server.listen(8)
        threading.Thread(target=self._serve, name="evolver-hardware-ipc", daemon=True).start()

    def close(self) -> None:
        self._stop.set()
        if self._server:
            self._server.close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except OSError:
                break
            with conn:
                try:
                    response = {"ok": True, "result": self.dispatch(_recv(conn))}
                except Exception as error:
                    response = {"ok": False, "error": str(error), "kind": error.__class__.__name__}
                try:
                    _send(conn, response)
                except OSError:
                    # The client may time out and close while hardware work is
                    # still in progress.  A failed response belongs to that
                    # connection and must not kill the accept loop.
                    pass

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        operation = request.get("operation")
        if operation == "discover":
            return self.service.discover()
        if operation == "protocol_test":
            return _protocol_test(self.service)
        if operation == "provision_identity":
            if request.get("physical") is not True:
                raise PermissionError("identity provisioning requires physical opt-in")
            operator = request.get("operator")
            device_id = request.get("device_id")
            owner_id = request.get("owner_id")
            if not all(isinstance(value, str) and value for value in (operator, device_id, owner_id)):
                raise ValueError("device_id, owner_id, and operator are required")
            return self.service.provision_identity(device_id=device_id, owner_id=owner_id,
                                                   operator=operator,
                                                   command_id=request.get("command_id")).as_json()
        if operation in READ_OPERATIONS - {"discover", "protocol_test"}:
            target = request.get("target_identity")
            if not isinstance(target, str): raise ValueError("target_identity is required")
            return self.service.command(operation, target, request.get("parameters") or {}).as_json()
        if operation == "lease_acquire":
            return self.store.acquire_local_commissioning_lease(str(request.get("operator", "")), int(request.get("ttl_seconds", 900)))
        if operation == "lease_status":
            return self.store.local_commissioning_lease_status()
        if operation == "lease_release":
            return self.store.release_local_commissioning_lease(str(request.get("operator", "")))
        if operation == "layout_record":
            target = request.get("target_identity")
            operator = request.get("operator")
            positions = request.get("positions")
            if not isinstance(target, str) or not isinstance(operator, str) or not isinstance(positions, dict):
                raise ValueError("layout record requires target_identity, operator, and positions")
            instrument = next((item for item in self.store.list_instruments() if item.get("device_identity") == target), None)
            if not isinstance(instrument, dict): raise EdgeStoreError("layout target identity is not registered")
            normalized = {int(channel): value for channel, value in positions.items() if isinstance(channel, str) and channel.isdigit()}
            if len(normalized) != len(positions): raise ValueError("layout channels must be decimal strings")
            return self.store.record_physical_layout(instrument_id=instrument["id"], positions=normalized,
                                                     operator=operator, device_identity=target)
        if operation in ACTUATOR_OPERATIONS:
            if request.get("physical") is not True: raise PermissionError("physical opt-in is required")
            target = request.get("target_identity")
            operator = request.get("operator")
            if not isinstance(target, str) or not isinstance(operator, str) or not operator: raise ValueError("operator and target_identity are required")
            return self.service.command(operation, target, request.get("parameters") or {}, command_id=request.get("command_id", str(uuid4())),
                                        operator=operator, lease_token=request.get("lease_token"), lease_owner=operator,
                                        require_lease=True, controller_generation=int(request.get("controller_generation", 0))).as_json()
        raise ValueError("unsupported typed hardware IPC operation")


def _timeout_for_request(payload: dict[str, Any], timeout: float | None) -> float:
    operation = payload.get("operation")
    effective = (PROVISIONING_IPC_TIMEOUT_SECONDS if operation == "provision_identity"
                 else DEFAULT_IPC_TIMEOUT_SECONDS) if timeout is None else timeout
    if effective <= 0:
        raise ValueError("hardware IPC timeout must be positive")
    if operation == "provision_identity" and effective <= PROVISIONING_INNER_BUDGET_SECONDS:
        raise ValueError("provisioning IPC timeout must exceed its inner three-exchange budget")
    return effective


def request(path: str | Path, payload: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
    deadline = time.monotonic() + _timeout_for_request(payload, timeout)
    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_MESSAGE: raise ValueError("hardware IPC request is too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(max(0.0, deadline - time.monotonic())); sock.connect(str(path))
        sock.settimeout(max(0.0, deadline - time.monotonic())); sock.sendall(data)
        sock.settimeout(max(0.0, deadline - time.monotonic()))
        response = _recv(sock)
    if not response.get("ok"): raise RuntimeError(response.get("error", "hardware service rejected request"))
    return response["result"]
