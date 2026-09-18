"""Action adapters for central status, host-runtime gating, and releases.

This module is deliberately an adapter boundary.  It does not own a catalog,
start a service, construct Docker commands, or reimplement release policy.
Callers receive either read-only projections or a delegated release operation.
"""
from __future__ import annotations

import os
from argparse import ArgumentParser, Namespace
from http import HTTPStatus
from pathlib import Path
from typing import Any, Callable, Mapping

from . import evolver_controller, runtime_debug


class HostRuntimeGateError(PermissionError):
    """The caller has not explicitly entered the host-runtime context."""


# This is an allowlist of service identities, not an instruction to operate
# them.  The default is intentionally empty at the execution boundary.
HOST_RUNTIME_SERVICES = frozenset({"webui", "evolver-control", "db", "migrate"})
HOST_RUNTIME_CONTEXT = "host-runtime"


def central_server_status(*, metadata: Callable[[], Mapping[str, Any]] = runtime_debug.metadata) -> dict[str, Any]:
    """Return central server status without probing or changing host state."""
    observed = dict(metadata())
    return {"status": "ok", "component": "central-server", "health_endpoint": "/health", "runtime": observed}


def host_runtime_context(*, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Describe whether the explicitly selected host-runtime context is active."""
    values = os.environ if environ is None else environ
    context = values.get("META_WEBUI_RUNTIME_CONTEXT", "").strip()
    enabled = values.get("META_WEBUI_HOST_RUNTIME_ENABLED", "").strip().lower() == "true"
    return {"context": context or None, "enabled": enabled and context == HOST_RUNTIME_CONTEXT,
            "allowed_services": sorted(HOST_RUNTIME_SERVICES), "executed": False}


def require_host_runtime_service(service: str, *, environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Validate a service identity and context; never execute a runtime action."""
    if service not in HOST_RUNTIME_SERVICES:
        raise HostRuntimeGateError(f"host-runtime service is not allowlisted: {service!r}")
    context = host_runtime_context(environ=environ)
    if not context["enabled"]:
        raise HostRuntimeGateError("host-runtime context is not enabled")
    return {"service": service, "context": HOST_RUNTIME_CONTEXT, "allowed": True, "executed": False}


def release_catalog(*, state_root: Path | None = None) -> tuple[Any, dict[str, Any]]:
    """Delegate to the central configured-release catalog read model."""
    return evolver_controller.configured_release_catalog(state_root=state_root)


def release_history(*, controller_id: str | None = None, state_root: Path | None = None) -> tuple[Any, dict[str, Any]]:
    """Delegate to the central release history read model."""
    return evolver_controller.release_history(controller_id=controller_id, state_root=state_root)


def release_defaults() -> dict[str, Any]:
    """Expose the existing release command defaults from its single owner."""
    from tools import evolver_release

    build_parser = ArgumentParser(add_help=False)
    evolver_release.add_build_options(build_parser)
    defaults = vars(build_parser.parse_args([]))
    return {"output": defaults["output"], "validator_python": defaults["validator_python"],
            "publish_root": Path("releases/evolver")}


def release_builder_command(args: Namespace, output: Path) -> list[str]:
    """Build the canonical builder command through the existing coordinator."""
    from tools import evolver_release

    return evolver_release.build_command(args, output)


def release_build(parameters: Mapping[str, Any] | None = None, *,
                  operator: evolver_controller.OperatorIdentity | None = None,
                  runner: Callable[[list[str]], None] | None = None) -> tuple[HTTPStatus, dict[str, Any]]:
    """Authenticate and invoke the existing production release coordinator.

    The action accepts only the options already exposed by ``add_build_options``;
    the coordinator and production builder remain the owners of build policy.
    """
    denied = evolver_controller._require_operator(operator, "update_controller")
    if denied:
        return denied
    from tools import evolver_release

    supplied = dict(parameters or {})
    parser = ArgumentParser(add_help=False)
    evolver_release.add_build_options(parser)
    defaults = vars(parser.parse_args([]))
    allowed = set(defaults)
    options = {key: value for key, value in supplied.items() if key in allowed and value is not None}
    for key in {"output", "nixos_bossac", "nixos_bossac_store_root", "arduino_cli", "arduino_data",
                "arduino_libraries", "python_runtime"}:
        if key in options:
            options[key] = Path(options[key])
    args = Namespace(**{**defaults, **options})
    output = Path(args.output)
    (runner or evolver_release.run)(release_builder_command(args, output))
    resolved = (evolver_release.ROOT / output).resolve() if not output.is_absolute() else output.resolve()
    return HTTPStatus.OK, {"status": "built", "output": str(resolved)}


def release_validate(release: Path, installer: Path | None = None) -> None:
    """Delegate release validation to the existing release coordinator."""
    from tools import evolver_release

    evolver_release.validate(release, installer)


def release_publish(release: Path, destination_root: Path, installer: Path | None = None) -> Path:
    """Delegate immutable publication to the existing release coordinator."""
    from tools import evolver_release

    return evolver_release.publish(release, destination_root, installer)


def release_action_registry() -> dict[str, Callable[..., Any]]:
    """Return stable adapter bindings for an action host to register."""
    return {
        "server.status": central_server_status,
        "server.runtime.service-context": require_host_runtime_service,
        "evolver.release.catalog": release_catalog,
        "evolver.release.history": release_history,
        "evolver.release.defaults": release_defaults,
        "evolver.release.builder-command": release_builder_command,
        "evolver.release.build": release_build,
        "evolver.release.validate": release_validate,
        "evolver.release.publish": release_publish,
    }
