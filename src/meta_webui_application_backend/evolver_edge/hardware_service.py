"""Systemd-oriented owner for safe physical min-eVOLVER observation."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import time
from typing import Callable

from .hardware import (HardwareService, HardwareUnavailableError, LocalSerialTransport,
                        ProbeOutcome, discover_ports)
from .hardware_ipc import HardwareIPCServer
from .store import EdgeStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evolver-hardware", description="exclusive min-eVOLVER hardware service")
    parser.add_argument("--state-root", default=os.environ.get("EVOLVER_STATE_ROOT", "/var/lib/evolver-controller"))
    parser.add_argument("--port", help="explicit serial port; required when more than one ACM device is present")
    parser.add_argument("--interval", type=float, default=10.0, help="safe sensor poll interval in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.interval <= 0:
        raise SystemExit("--interval must be positive")
    with EdgeStore(Path(args.state_root)) as store:
        # The daemon is the sole typed IPC owner for the explicitly physical
        # identity-provisioning operation. Keep the request-level
        # --physical/operator/blank-state guards in HardwareService intact.
        service = HardwareService(store, LocalSerialTransport(args.port or "/dev/ttyACM0"),
                                  allow_physical=True, daemon_capable=True)
        ipc = HardwareIPCServer(store, service, os.environ.get("EVOLVER_HARDWARE_SOCKET", "/run/evolver-controller/hardware.sock"))
        ipc.start()
        while True:
            poll_once(store, requested_port=args.port, service=service)
            time.sleep(args.interval)


def poll_once(store: EdgeStore, *, requested_port: str | None,
              discover: Callable[[str | None], list[str]] = discover_ports,
              transport_factory: Callable[[str], LocalSerialTransport] = LocalSerialTransport,
              service: HardwareService | None = None) -> None:
    """Observe one safe polling cycle.

    USB ACM names are transport details, not identities.  Re-enumeration and
    temporary removal are expected operational states, so failure is retained
    as service liveness rather than terminating the observer and requiring a
    human/systemd restart.  A later cycle rediscovers the provisioned device
    and derives the same instrument id from its firmware identity.
    """
    ports = discover(requested_port)
    transport = {"kind": "usb_serial", "candidates": list(ports), "rescan": True}
    if not ports:
        store.record_hardware_observation({"source": "physical", "connection_state": "disconnected",
                                           "transport": transport,
                                           "transport_evidence": {"event": "disconnect", "reason": "no_usb_candidates"}})
        for instrument in store.list_instruments():
            store.record_instrument_transport(instrument["id"], connection_state="disconnected",
                                               transport=transport, reason="no_usb_candidates")
        return
    if len(ports) != 1:
        store.record_hardware_observation({"source": "physical", "connection_state": "ambiguous",
                                           "transport": transport,
                                           "transport_evidence": {"event": "rescan", "reason": "multiple_usb_candidates"},
                                           "identity_ambiguous": True})
        for instrument in store.list_instruments():
            store.record_instrument_transport(instrument["id"], connection_state="ambiguous",
                                               transport=transport, reason="multiple_usb_candidates")
        return
    try:
        service = service or HardwareService(store, transport_factory(ports[0]), allow_physical=True)
        # The service remains the sole owner, but USB ACM names may change
        # after re-enumeration.  Update its transport endpoint before the
        # next bounded session; never create a second serial client.
        if service.transport.port != ports[0]:
            service.transport = transport_factory(ports[0])
        instrument = service.discover()
        if "id" in instrument:
            service.capture_telemetry(instrument["id"])
    except HardwareUnavailableError as error:
        # The next interval repeats discovery; never infer identity from a
        # disappearing/reappearing tty path.
        outcome = getattr(error, "outcome", ProbeOutcome.OPEN)
        evidence = getattr(error, "evidence", {"detail": str(error)})
        # A permission/ownership problem is degraded rather than a physical
        # disconnect; protocol and identity failures are ambiguous evidence,
        # and timeout/open failures mean the endpoint is currently absent.
        connection_state = (
            "degraded" if outcome in {ProbeOutcome.PERMISSION, ProbeOutcome.BUSY}
            else "ambiguous" if outcome in {ProbeOutcome.PROTOCOL, ProbeOutcome.MALFORMED,
                                             ProbeOutcome.STATUS, ProbeOutcome.IDENTITY}
            else "disconnected"
        )
        store.record_hardware_observation({"source": "physical", "connection_state": connection_state,
                                           "transport": transport,
                                           "transport_evidence": {"event": "probe_failed", "reason": outcome.value,
                                                                  **dict(evidence)},
                                           "probe_outcome": outcome.value,
                                           "identity_ambiguous": outcome is ProbeOutcome.IDENTITY or outcome is ProbeOutcome.MALFORMED})
        for known in store.list_instruments():
            store.record_instrument_transport(known["id"], connection_state=connection_state,
                                               transport={**transport, "path": ports[0]}, reason=outcome.value)
        return


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
