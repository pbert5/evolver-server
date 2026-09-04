"""Safe controller software update planning.

The central service may describe a desired *release*, but it never sends a
shell command.  A host-local backend owns installation and this module fences
updates while an experiment can still be affected.  Firmware is deliberately
outside this contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
import subprocess
from typing import Callable, Protocol, Sequence

from .store import EdgeStore, EdgeStoreError


def record_installed_release(store: EdgeStore, release: str) -> str:
    """Record the immutable release after host activation succeeds."""
    if not isinstance(release, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release):
        raise EdgeStoreError("release must be a simple pinned release identifier")
    store.set_meta("controller_software_release", release)
    return release


class UpdatePolicy(StrEnum):
    MANUAL = "manual"
    WHEN_IDLE = "when_idle"
    AUTOMATIC = "automatic"


class UpdateBackend(Protocol):
    """A host-local implementation that installs a named controller release."""

    name: str

    def install(self, release: str) -> None: ...


Runner = Callable[[Sequence[str]], None]


def _run(command: Sequence[str]) -> None:
    subprocess.run(command, check=True)  # nosec B603: fixed executable/argument vector


class ComposeUpdateBackend:
    """The sole edge software deployment adapter: host-owned Compose."""
    name = "compose"

    def __init__(self, *, compose_file: str | None = None, runner: Runner = _run) -> None:
        self.compose_file, self.runner = compose_file, runner

    def install(self, release: str) -> None:
        if not self.compose_file:
            raise EdgeStoreError("Compose deployment is host-owned; set EVOLVER_COMPOSE_FILE")
        self.runner(["docker", "compose", "-f", self.compose_file, "up", "-d", "--build"])


@dataclass(frozen=True)
class UpdateDecision:
    release: str
    policy: UpdatePolicy
    backend: str
    action: str
    reason: str | None = None


class UpdateManager:
    """Policy gate for the root-owned Compose deployment."""

    def __init__(self, store: EdgeStore, backend: UpdateBackend, *, policy: UpdatePolicy = UpdatePolicy.WHEN_IDLE):
        self.store, self.backend, self.policy = store, backend, policy

    def active_runs(self) -> list[dict]:
        return [run for run in self.store.list_runs() if run["state"] in {"running", "paused", "stopping"}]

    def plan(self, release: str, *, explicit: bool = False) -> UpdateDecision:
        """Return the guarded action without changing the installed release.

        ``check`` is deliberately local and side-effect free.  Release
        discovery belongs to a signed release catalog, not to an arbitrary
        command supplied by the WebUI or terminal.
        """
        if not isinstance(release, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release):
            raise EdgeStoreError("release must be a simple pinned release identifier")
        active = self.active_runs()
        if active and not explicit:
            return UpdateDecision(release, self.policy, self.backend.name, "deferred", "active runs present")
        if self.policy is UpdatePolicy.MANUAL and not explicit:
            return UpdateDecision(release, self.policy, self.backend.name, "deferred", "manual policy")
        return UpdateDecision(release, self.policy, self.backend.name, "ready")

    def request(self, release: str, *, explicit: bool = False) -> UpdateDecision:
        decision = self.plan(release, explicit=explicit)
        if decision.action == "deferred":
            return decision
        # Even "automatic" is never permission to replace the runtime under a
        # live run.  ``explicit`` is a local maintenance acknowledgement.
        self.backend.install(release)
        record_installed_release(self.store, release)
        return UpdateDecision(release, self.policy, self.backend.name, "installed")
