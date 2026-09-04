"""Pure controller lifecycle planning.

The planner contains policy only.  It reads an inspection snapshot and emits
the actions, warnings, and confirmation requirements that an executor may
apply.  In particular, a server-hosted installer must not infer takeover from
the fact that it was invoked.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Operation = Literal[
    "install", "repair", "update", "clean-reinstall", "uninstall",
    "handoff", "forced-adoption", "factory-reset",
]

_DISRUPTIVE = {"update", "clean-reinstall", "uninstall", "handoff", "forced-adoption", "factory-reset"}


@dataclass(frozen=True)
class ControllerLifecyclePlan:
    operation: Operation
    current_installation: bool
    current_release: str | None
    target_release: str | None
    current_binding: dict | None
    durable_state_present: bool
    target_server: str | None
    connectivity: str | None
    active_runs: list[dict] = field(default_factory=list)
    software_actions: tuple[str, ...] = ()
    binding_actions: tuple[str, ...] = ()
    state_actions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    requires_confirmation: bool = False
    blocked_reasons: tuple[str, ...] = ()
    confirmed: bool = False

    @property
    def ready(self) -> bool:
        return not self.blocked_reasons and (not self.requires_confirmation or self.confirmed)


def plan_lifecycle(*, operation: Operation, current_installation: bool,
                   current_release: str | None = None, target_release: str | None = None,
                   current_binding: dict | None = None, target_server: str | None = None,
                   connectivity: str | None = None, active_runs: list[dict] | None = None,
                   confirmed: bool = False, durable_state_present: bool = False) -> ControllerLifecyclePlan:
    """Build a side-effect-free lifecycle plan from inspected facts."""
    runs = list(active_runs or [])
    warnings: list[str] = []
    blocked: list[str] = []
    software: tuple[str, ...] = ()
    binding: tuple[str, ...] = ()
    state: tuple[str, ...] = ()

    if operation == "install":
        if current_installation or current_binding:
            blocked.append("an existing controller installation or binding was detected; choose an explicit lifecycle operation")
        software, binding, state = ("create runtime",), ("enroll",), ("create durable state",)
    elif operation == "repair":
        if not current_installation:
            blocked.append("repair requires an installed controller runtime")
        software = ("repair owned services and links",)
        binding, state = ("keep binding",), ("keep durable state",)
    elif operation == "update":
        if not current_installation:
            blocked.append("update requires an installed controller runtime")
        software = ("replace runtime with target release",) if current_release != target_release else ()
        binding, state = ("keep binding",), ("keep durable state",)
        if current_release == target_release:
            warnings.append("installed release already matches the selected release; no update is required")
    elif operation == "clean-reinstall":
        if not current_installation and not durable_state_present and not current_binding:
            blocked.append("clean reinstall requires existing durable controller state or an installed runtime")
        software = ("recreate installer-owned runtime paths",)
        binding, state = ("keep binding",), ("keep durable state",)
        warnings.append("controller identity, credentials, binding, runs, calibration, and firmware state are preserved")
    elif operation == "uninstall":
        if not current_installation:
            blocked.append("no installed controller runtime was detected")
        software, binding, state = ("remove installer-owned runtime",), ("keep binding",), ("keep durable state",)
        warnings.append("controller identity and local state will be preserved")
    elif operation == "handoff":
        if not current_binding:
            blocked.append("move requires an existing controller binding")
        if not target_server:
            blocked.append("move requires a target server")
        if current_binding and target_server and current_binding.get("server_url") == target_server.rstrip("/"):
            blocked.append("target server is already the current server; no move is required")
        binding, state = ("release old generation", "enroll new server"), ("keep durable state",)
        warnings.append("the old WebUI must release the current generation before ownership changes")
    elif operation == "forced-adoption":
        if not current_binding:
            blocked.append("forced adoption requires an existing controller binding")
        if not target_server:
            blocked.append("forced adoption requires a target server")
        binding, state = ("fence old generation", "replace binding"), ("record adoption decision", "keep durable state")
        warnings.extend(("the old WebUI will not participate in the transfer", "a returning old server remains fenced"))
        if runs:
            blocked.append("active/non-terminal runs make forced adoption unsafe")
        if not confirmed:
            warnings.append("explicit operator confirmation is required")
    elif operation == "factory-reset":
        if not current_installation and not current_binding:
            blocked.append("no controller state was detected")
        software, binding, state = ("remove installer-owned runtime",), ("erase identity and binding",), ("erase durable state",)
        warnings.extend(("this erases controller identity, credentials, binding, and durable state", "export recovery state first if it is needed later"))
        if not confirmed:
            warnings.append("type the controller name or ID to confirm this destructive action")

    if runs and operation in _DISRUPTIVE and operation not in {"factory-reset", "forced-adoption"}:
        blocked.append("active/non-terminal runs exist; stop them or use the existing explicit maintenance override")
    return ControllerLifecyclePlan(operation, current_installation, current_release, target_release,
                                  current_binding, target_server.rstrip("/") if target_server else None,
                                  durable_state_present, connectivity, runs, software, binding, state, tuple(warnings),
                                  bool(warnings) and operation in {"clean-reinstall", "uninstall", "handoff", "forced-adoption", "factory-reset"},
                                  tuple(blocked), confirmed)
