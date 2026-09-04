"""Local operator CLI over the same durable edge domain store."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .bundle import resolve_bundle
from .store import EdgeStore, EdgeStoreError, canonical_digest
from .sync import SyncClient
from .install import (detect_backend, inspect_installation, repair_installation, status_json, systemd_unit,
                      uninstall_installation)
from .lifecycle import plan_lifecycle
from .update import NativePackageBackend, NixUpdateBackend, OCIUpdateBackend, UpdateManager, UpdatePolicy, record_installed_release
from .doctor import doctor_report


def _root(value: str | None) -> Path:
    return Path(value or os.environ.get("EVOLVER_STATE_ROOT", "/var/lib/evolver-controller"))


_SENSITIVE_KEY_PARTS = ("credential", "password", "secret", "token", "private_key", "api_key", "authorization")


def _redact(value: Any) -> Any:
    """Redact sensitive fields structurally before operator serialization."""
    if isinstance(value, dict):
        return {key: ("<redacted>" if any(part in str(key).lower() for part in _SENSITIVE_KEY_PARTS)
                      else _redact(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    return value


def _emit(value: Any) -> None:
    print(json.dumps(_redact(value), indent=2, sort_keys=True, default=str))


def _compatibility_argv(argv: list[str]) -> list[str]:
    """Translate grouped operator spellings to the existing local actions.

    The edge CLI's flat commands are the implementation contract.  These
    aliases are presentation compatibility only: they never add a transport,
    central action, or physical operation.  Longest prefixes must be checked
    first so ``local run list`` does not become ``run list`` accidentally.
    """
    aliases: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
        (("local", "run", "list"), ("runs",)),
        (("local", "runs"), ("runs",)),
        (("local", "run"), ("run",)),
        (("local", "diagnostics"), ("doctor",)),
        (("local", "diagnostic"), ("doctor",)),
        (("local", "status"), ("status",)),
        (("local", "server"), ("status",)),
        (("local", "binding"), ("binding",)),
        (("local", "recovery"), ("recovery",)),
        (("local", "release"), ("update",)),
        (("server", "status"), ("status",)),
        (("server", "binding"), ("binding",)),
        (("server",), ("status",)),
        (("binding", "show"), ("binding",)),
        (("binding", "status"), ("binding",)),
        (("recovery", "show"), ("recovery",)),
        (("recovery", "status"), ("recovery",)),
        (("release", "status"), ("update", "status")),
        (("release", "check"), ("update", "check")),
        (("release", "apply"), ("update", "apply")),
        (("diagnostics",), ("doctor",)),
        (("diagnostic",), ("doctor",)),
        (("read-only", "diagnostics"), ("doctor",)),
        (("runs", "list"), ("runs",)),
        (("run", "list"), ("runs",)),
    )
    for source, target in aliases:
        if tuple(argv[:len(source)]) == source:
            return [*target, *argv[len(source):]]
    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evolverctl", description="eVOLVER controller local operator CLI")
    parser.add_argument("--state-root", help="persistent controller state directory")
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll"); enroll.add_argument("--server", required=True); enroll.add_argument("--token", required=True)
    enroll.add_argument("--mode", choices=("repair", "live_handoff", "forced_adoption"),
                        help="required when this controller already has a binding")
    enroll.add_argument("--confirm-forced-adoption", action="store_true",
                        help="explicit operator acknowledgement for recovery takeover")
    commands.add_parser("status"); commands.add_parser("runs"); commands.add_parser("binding"); commands.add_parser("recovery")
    release = commands.add_parser("record-installed-release", help=argparse.SUPPRESS)
    release.add_argument("release")
    lifecycle = commands.add_parser("lifecycle-plan", help="inspect and plan a lifecycle operation without mutating the host")
    lifecycle.add_argument("--operation", choices=("install", "repair", "update", "clean-reinstall", "uninstall", "handoff", "forced-adoption", "factory-reset"), required=True)
    lifecycle.add_argument("--server")
    lifecycle.add_argument("--release")
    lifecycle.add_argument("--current-state", type=Path,
                           help="JSON inspection snapshot supplied by an installer")
    lifecycle.add_argument("--confirmed", action="store_true")
    export_state = commands.add_parser("export-state", help="export credential-free recovery data to recovery.tar.zst")
    export_state.add_argument("archive", nargs="?", default="recovery.tar.zst")
    import_state = commands.add_parser("import-state", help="import recovery data into a fresh local state root")
    import_state.add_argument("archive")
    commands.add_parser("doctor", help="run read-only local controller and central health checks")
    sync = commands.add_parser("sync"); sync.add_argument("--loop", action="store_true"); sync.add_argument("--interval", type=float, default=10.0)
    run = commands.add_parser("run"); run_sub = run.add_subparsers(dest="run_command", required=True)
    for action in ("show", "pause", "resume", "stop", "events", "telemetry"):
        item = run_sub.add_parser(action); item.add_argument("run_id")
        if action in {"pause", "resume", "stop"}: item.add_argument("--based-on-revision", type=int)
    # Inventory is durable edge-domain data; simulator and hardware adapters
    # merely populate the same contract.
    commands.add_parser("controllers"); commands.add_parser("instruments")
    instrument = commands.add_parser("instrument"); instrument_sub = instrument.add_subparsers(dest="instrument_command", required=True)
    show = instrument_sub.add_parser("show"); show.add_argument("instrument_id")
    tui = commands.add_parser("tui", help="run the local configured Textual operator UI")
    tui.add_argument("--page", choices=("overview", "controllers", "instruments", "runs", "recovery", "maintenance"), default="overview")
    install = commands.add_parser("install-status"); install.add_argument("--unit", action="store_true")
    update = commands.add_parser("update", help="inspect or apply a local controller software release")
    update_sub = update.add_subparsers(dest="update_command", required=True)
    update_sub.add_parser("status")
    check = update_sub.add_parser("check"); check.add_argument("release")
    apply = update_sub.add_parser("apply"); apply.add_argument("release")
    uninstall = commands.add_parser("uninstall", help="remove eVOLVER software while preserving state")
    uninstall.add_argument("--purge", action="store_true", help="also delete local controller state (destructive)")
    uninstall.add_argument("--yes", action="store_true", help="confirm destructive maintenance in automation")
    uninstall.add_argument("--force-active", action="store_true", help="explicitly override active-run protection")
    uninstall.add_argument("--operator", help="operator attribution for the lifecycle audit")
    commands.add_parser("repair", help="restore owned services and links from the current release")
    simulator = commands.add_parser("simulator"); sim_sub = simulator.add_subparsers(dest="simulator_command", required=True)
    start = sim_sub.add_parser("start"); start.add_argument("--instruments", type=int, default=1)
    create = sim_sub.add_parser("create-run", help="create a safe simulated run from a declarative plan")
    create.add_argument("run_id")
    create.add_argument("--bundle-id", required=True)
    create.add_argument("--execution-plan", required=True,
                        help="JSON declarative state-machine plan; it is stored in an immutable ExperimentBundle")
    create.add_argument("--instruments", type=int, default=1)
    tick = sim_sub.add_parser("tick", help="advance a durable simulated run without network or hardware")
    tick.add_argument("run_id")
    tick.add_argument("--ticks", type=int, default=1)
    tick.add_argument("--instruments", type=int, default=1)
    firmware = commands.add_parser("firmware", help="verify or developer-build the pinned firmware")
    firmware.add_argument("action", choices=("build", "upload", "verify", "preflight"))
    firmware.add_argument("--port")
    firmware.add_argument("--artifact", type=Path)
    firmware.add_argument("--physical", action="store_true")
    firmware.add_argument("--operator")
    firmware.add_argument("--sha256")
    hardware = commands.add_parser("hardware", help="safe hardware-service diagnostics and gated maintenance")
    hardware_sub = hardware.add_subparsers(dest="hardware_command", required=True)
    hardware_sub.add_parser("discover")
    hardware_sub.add_parser("protocol-test")
    quarantine = hardware_sub.add_parser("quarantine-command", help="DB-only resolution of one interrupted command")
    quarantine.add_argument("command_id"); quarantine.add_argument("--operator", required=True)
    quarantine.add_argument("--reason-kind", required=True)
    quarantine.add_argument("--requested-device"); quarantine.add_argument("--requested-owner")
    quarantine.add_argument("--observed-device"); quarantine.add_argument("--observed-owner")
    provision = hardware_sub.add_parser("provision-identity", help="provision a blank device identity")
    provision.add_argument("--device-id", required=True); provision.add_argument("--owner-id", required=True)
    provision.add_argument("--operator", required=True); provision.add_argument("--physical", action="store_true")
    actuator = hardware_sub.add_parser("actuate", help="one bounded maintenance command; physical opt-in required")
    actuator.add_argument("operation", choices=("set_output", "pulse_pump", "set_stir", "pulse_heater", "safe_stop"))
    actuator.add_argument("--target", required=True)
    actuator.add_argument("--channel", type=int, default=0)
    actuator.add_argument("--duration-ms", type=int)
    actuator.add_argument("--level", type=int)
    actuator.add_argument("--physical", action="store_true")
    actuator.add_argument("--operator", help="audited operator attribution")
    actuator.add_argument("--lease-token")
    lease = hardware_sub.add_parser("lease", help="bounded local commissioning lease")
    lease_sub = lease.add_subparsers(dest="lease_command", required=True)
    acquire = lease_sub.add_parser("acquire"); acquire.add_argument("--operator", required=True); acquire.add_argument("--ttl-seconds", type=int, default=900)
    lease_sub.add_parser("status")
    release = lease_sub.add_parser("release"); release.add_argument("--operator", required=True)
    layout = hardware_sub.add_parser("layout", help="record physical vial orientation evidence")
    layout.add_argument("--target", required=True); layout.add_argument("--operator", required=True)
    layout.add_argument("--channel", type=int, required=True); layout.add_argument("--physical-side", choices=("left", "right", "unconfirmed"), required=True)
    layout.add_argument("--method", choices=("operator_observed", "inferred_two_position_profile"), required=True)
    hardware.add_argument("--socket", default=os.environ.get("EVOLVER_HARDWARE_SOCKET", "/run/evolver-controller/hardware.sock"))
    hardware.add_argument("--timeout", type=float, help="bounded hardware IPC timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_arguments = sys.argv[1:] if argv is None else list(argv)
    # Global options precede grouped aliases in the documented shell syntax.
    # Normalize only the command portion so ``--state-root PATH server`` is
    # equivalent to ``server --state-root PATH`` without changing parsing.
    prefix: list[str] = []
    while raw_arguments and raw_arguments[0] == "--state-root":
        prefix.extend(raw_arguments[:2])
        raw_arguments = raw_arguments[2:]
    arguments = [*prefix, *_compatibility_argv(raw_arguments)]
    args = build_parser().parse_args(arguments)
    if args.command == "uninstall":
        try:
            _emit(uninstall_installation(_root(args.state_root), purge=args.purge, confirm=args.yes,
                                         force_active=args.force_active, operator=args.operator))
            return 0
        except (RuntimeError, ValueError, OSError) as error:
            _emit({"error": str(error)}); return 2
    if args.command == "repair":
        try:
            _emit(repair_installation(_root(args.state_root))); return 0
        except (RuntimeError, ValueError, OSError) as error:
            _emit({"error": str(error)}); return 2
    if args.command == "lifecycle-plan":
        if args.current_state is not None:
            snapshot = json.loads(args.current_state.read_text(encoding="utf-8"))
            controller = snapshot.get("controller")
            binding = snapshot.get("binding")
            active_runs = snapshot.get("active_runs", snapshot.get("runs", []))
            current_release = snapshot.get("installed_release")
            runtime_installed = snapshot.get("runtime_installed", snapshot.get("controller") is not None)
            durable_state_present = snapshot.get("durable_state_present", snapshot.get("controller") is not None or snapshot.get("binding") is not None)
        else:
            status = inspect_installation(_root(args.state_root))
            controller, binding, active_runs, current_release = (status.controller, status.binding,
                                                                  status.active_runs, status.installed_release)
            runtime_installed, durable_state_present = status.runtime_installed, status.durable_state_present
        plan = plan_lifecycle(operation=args.operation, current_installation=runtime_installed,
                              current_release=current_release, target_release=args.release,
                              current_binding=binding, target_server=args.server,
                              connectivity=(controller or {}).get("connection_state") if controller else None,
                              active_runs=active_runs, confirmed=args.confirmed,
                              durable_state_present=durable_state_present)
        _emit(plan.__dict__)
        return 2 if plan.blocked_reasons else 0
    with EdgeStore(_root(args.state_root)) as store:
        if args.command == "record-installed-release":
            try:
                _emit({"installed_release": record_installed_release(store, args.release)})
                return 0
            except Exception as error:
                _emit({"error": str(error)}); return 2
        if args.command == "enroll":
            client = SyncClient(store)
            # Keep the decision auditable in CLI output.  It intentionally
            # does not infer a replacement merely because the server changed.
            plan = client.enrollment_plan(server=args.server)
            try:
                result = client.enroll(server=args.server, token=args.token, mode=args.mode,
                                       operator_confirmed=args.confirm_forced_adoption)
            except (RuntimeError, ValueError) as error:
                _emit({"enrollment": plan, "error": str(error)}); return 2
            _emit({"enrollment": plan, "result": result}); return 0
        if args.command == "status":
            _emit({"controller": store.identity(), "binding": store.binding(), "runs": store.list_runs()}); return 0
        if args.command == "doctor":
            report = doctor_report(store)
            _emit(report)
            return 2 if report["summary"]["FAIL"] else 0
        if args.command == "runs": _emit(store.list_runs()); return 0
        if args.command == "binding": _emit(store.binding()); return 0
        if args.command == "install-status":
            _emit(systemd_unit() if args.unit else status_json(store.root)); return 0
        if args.command == "update":
            manager = UpdateManager(store, _update_backend(), policy=_update_policy())
            if args.update_command == "status":
                _emit({"installed_release": store.meta("controller_software_release"),
                       "desired_release": store.meta("desired_controller_software_release"),
                       "policy": manager.policy.value, "backend": manager.backend.name,
                       "active_runs": [run["id"] for run in manager.active_runs()]})
                return 0
            try:
                if args.update_command == "check":
                    _emit(manager.plan(args.release).__dict__); return 0
                # Applying from evolverctl is a local, explicit maintenance
                # action.  The manager still records the release durably.
                _emit(manager.request(args.release, explicit=True).__dict__); return 0
            except Exception as error:
                _emit({"error": str(error)}); return 2
        if args.command == "recovery": _emit(store.recovery_manifest()); return 0
        if args.command == "export-state":
            from .recovery import export_state
            _emit(export_state(store, args.archive)); return 0
        if args.command == "import-state":
            from .recovery import import_state
            try:
                _emit(import_state(store, args.archive)); return 0
            except (EdgeStoreError, OSError) as error:
                _emit({"error": str(error)}); return 2
        if args.command == "sync":
            client = SyncClient(store)
            if args.loop: client.run_loop(interval=args.interval)
            else: _emit(client.sync_once().__dict__)
            return 0
        if args.command == "controllers": _emit([store.identity()]); return 0
        if args.command == "instruments": _emit(store.list_instruments()); return 0
        if args.command == "instrument":
            try:
                _emit(store.instrument(args.instrument_id)); return 0
            except KeyError:
                _emit({"id": args.instrument_id, "error": "instrument not found"}); return 1
        if args.command == "tui":
            from .tui import run as run_tui
            return run_tui(store, page=args.page)
        if args.command == "simulator":
            # Simulator support is part of this distribution.  Constructing it
            # also derives stable inventory from the durable controller id, so
            # repeated operator invocations report the same instruments.
            from .simulator import EvolverSimulator
            simulator = EvolverSimulator(store, instruments=args.instruments)
            if args.simulator_command == "start":
                _emit({"controller": store.identity(), "instruments": simulator.inventory()}); return 0
            if args.simulator_command == "create-run":
                try:
                    plan = json.loads(args.execution_plan)
                except json.JSONDecodeError as error:
                    _emit({"error": f"execution plan must be JSON: {error}"}); return 2
                bundle = resolve_bundle({"id": args.bundle_id, "purpose": "test_fixture",
                                         "execution_mode": "declarative_state_machine", "execution_plan": plan,
                                         "calibration_requirements": []}, [])
                store.put_bundle(bundle)
                _emit(simulator.start_run(run_id=args.run_id, bundle_id=args.bundle_id)); return 0
            _emit({"run_id": args.run_id, "records": simulator.tick(run_ids=[args.run_id], ticks=args.ticks)})
            return 0
        if args.command == "firmware":
            from .firmware import main as firmware_main
            firmware_args = [args.action]
            if args.port: firmware_args += ["--port", args.port]
            if args.artifact: firmware_args += ["--artifact", str(args.artifact)]
            if args.physical: firmware_args += ["--physical"]
            if args.operator: firmware_args += ["--operator", args.operator]
            if args.sha256: firmware_args += ["--sha256", args.sha256]
            return firmware_main(firmware_args)
        if args.command == "hardware":
            if args.hardware_command == "quarantine-command":
                try:
                    _emit(store.quarantine_command(
                        args.command_id, operator=args.operator, reason_kind=args.reason_kind,
                        requested_identity={"device_id": args.requested_device, "owner_id": args.requested_owner},
                        observed_identity={"device_id": args.observed_device, "owner_id": args.observed_owner}))
                    return 0
                except (RuntimeError, ValueError, OSError) as error:
                    _emit({"error": str(error)}); return 2
            from .hardware_ipc import request
            socket_path = args.socket
            if args.hardware_command == "discover":
                _emit(request(socket_path, {"operation": "discover"}, args.timeout)); return 0
            if args.hardware_command == "protocol-test":
                _emit(request(socket_path, {"operation": "protocol_test"}, args.timeout)); return 0
            if args.hardware_command == "provision-identity":
                _emit(request(socket_path, {"operation": "provision_identity", "device_id": args.device_id,
                                            "owner_id": args.owner_id, "operator": args.operator,
                                            "physical": args.physical}, args.timeout)); return 0
            if args.hardware_command == "lease":
                if args.lease_command == "acquire": payload = {"operation": "lease_acquire", "operator": args.operator, "ttl_seconds": args.ttl_seconds}
                elif args.lease_command == "status": payload = {"operation": "lease_status"}
                else: payload = {"operation": "lease_release", "operator": args.operator}
                _emit(request(socket_path, payload, args.timeout)); return 0
            if args.hardware_command == "layout":
                _emit(request(socket_path, {"operation": "layout_record", "target_identity": args.target,
                                            "operator": args.operator, "positions": {str(args.channel): {
                                                "physical_side": args.physical_side, "method": args.method}}}, args.timeout)); return 0
            params = {"channel": args.channel}
            if args.operation == "set_output": params.update(output="od_led", level=args.level)
            elif args.operation == "pulse_pump": params.update(duration_ms=args.duration_ms)
            elif args.operation in {"set_stir", "pulse_heater"}: params.update(duration_ms=args.duration_ms, level=args.level)
            generation = int((store.binding() or {}).get("generation", 0))
            _emit(request(socket_path, {"operation": args.operation, "target_identity": args.target,
                                        "parameters": params, "physical": args.physical, "operator": args.operator,
                                        "lease_token": args.lease_token, "controller_generation": generation}, args.timeout)); return 0
        if args.command == "run":
            if args.run_command == "show": _emit(store.run(args.run_id)); return 0
            if args.run_command == "events": _emit(store.events_after(args.run_id)); return 0
            if args.run_command == "telemetry":
                _emit([record for item in store.recovery_manifest()["telemetry_ranges"] for record in store.telemetry_after(item["stream_id"]) if args.run_id in item["stream_id"]]); return 0
            run = store.run(args.run_id)
            revision = args.based_on_revision if args.based_on_revision is not None else run["current_revision"]
            state = {"pause": "paused", "resume": "running", "stop": "stopped"}[args.run_command]
            _emit(store.transition_run(run_id=args.run_id, state=state, based_on_revision=revision)); return 0
    return 1


def _update_policy() -> UpdatePolicy:
    try:
        return UpdatePolicy(os.environ.get("EVOLVER_UPDATE_POLICY", UpdatePolicy.WHEN_IDLE))
    except ValueError as exc:
        raise ValueError("EVOLVER_UPDATE_POLICY must be manual, when_idle, or automatic") from exc


def _update_backend():
    backend = detect_backend()
    if backend == "nix" and os.environ.get("EVOLVER_DEVELOPER_MODE") == "true" and os.environ.get("EVOLVER_NIX_FLAKE"):
        return NixUpdateBackend(flake=os.environ["EVOLVER_NIX_FLAKE"])
    if backend == "oci":
        return OCIUpdateBackend(image=os.environ.get("EVOLVER_OCI_IMAGE", "ghcr.io/pbert5/evolver-controller"),
                                runtime="podman" if os.environ.get("EVOLVER_OCI_RUNTIME") is None else os.environ["EVOLVER_OCI_RUNTIME"])
    return NativePackageBackend(package=os.environ.get("EVOLVER_NATIVE_PACKAGE", "evolver-controller"),
                                manager=os.environ.get("EVOLVER_NATIVE_PACKAGE_MANAGER", "apt-get"))


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(main())
