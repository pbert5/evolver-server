"""Canonical native eVOLVER release targets and host detection."""
from __future__ import annotations

import platform as _platform
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_RUNTIMES = {"glibc", "nixos"}
SUPPORTED_OS = {"linux"}
SUPPORTED_ARCHITECTURES = {"x86_64", "aarch64"}
PUBLISHABLE_TARGETS = frozenset({"linux-x86_64-glibc", "linux-x86_64-nixos"})
RESERVED_TARGETS = frozenset({"linux-aarch64-glibc"})


@dataclass(frozen=True, order=True)
class PlatformTarget:
    os: str
    architecture: str
    runtime: str

    def __post_init__(self) -> None:
        if self.os not in SUPPORTED_OS:
            raise ValueError(f"unknown target OS: {self.os}")
        if self.architecture not in SUPPORTED_ARCHITECTURES:
            raise ValueError(f"unknown target architecture: {self.architecture}")
        if self.runtime not in SUPPORTED_RUNTIMES:
            raise ValueError(f"unknown target runtime: {self.runtime}")

    @property
    def id(self) -> str:
        return f"{self.os}-{self.architecture}-{self.runtime}"

    @classmethod
    def parse(cls, value: str) -> "PlatformTarget":
        parts = value.split("-")
        if len(parts) != 3:
            raise ValueError(f"malformed platform target: {value}")
        target = cls(*parts)
        if target.id != value:
            raise ValueError(f"non-canonical platform target: {value}")
        return target

    def as_dict(self) -> dict[str, str]:
        return {"target": self.id, "os": self.os, "architecture": self.architecture, "runtime": self.runtime}


def normalize_architecture(machine: str | None = None) -> str:
    value = (machine or _platform.machine()).lower()
    aliases = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
    try:
        return aliases[value]
    except KeyError as exc:
        raise ValueError(f"unsupported native architecture: {machine or value}") from exc


def detect_runtime(*, os_release: Path = Path("/etc/os-release"), libc_name: str | None = None) -> str:
    values: dict[str, str] = {}
    try:
        for line in os_release.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value.strip().strip('"')
    except OSError:
        values = {}
    if values.get("ID") == "nixos" or "nixos" in values.get("ID_LIKE", "").split():
        return "nixos"
    if libc_name is None:
        libc_name, _ = _platform.libc_ver()
    if libc_name.lower() != "glibc":
        raise ValueError("unsupported Linux runtime: glibc is required")
    return "glibc"


def detect_target(*, machine: str | None = None, os_name: str | None = None,
                  os_release: Path = Path("/etc/os-release"), libc_name: str | None = None) -> PlatformTarget:
    normalized_os = (os_name or _platform.system()).lower()
    if normalized_os != "linux":
        raise ValueError(f"unsupported native operating system: {os_name or normalized_os}")
    return PlatformTarget("linux", normalize_architecture(machine), detect_runtime(os_release=os_release, libc_name=libc_name))
