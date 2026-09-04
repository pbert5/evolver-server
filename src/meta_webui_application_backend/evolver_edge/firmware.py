"""Offline-first SAMD21 firmware operations for the local edge CLI.

Building is a developer operation and requires an already-installed
``arduino-cli`` toolchain. Production installation uses the release binary;
it never runs ``core update-index`` or downloads a board package.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
from dataclasses import dataclass


FQBN = "SparkFun:samd:samd21_mini"
CANONICAL_BOSSA_VERSION = "1.7.0-arduino3"
CANONICAL_BOSSA_RELATIVE_PATH = Path("packages/arduino/tools/bossac") / CANONICAL_BOSSA_VERSION / "bossac"
CANONICAL_BOSSA_PROVENANCE_PATH = f"toolchain/arduino-data/{CANONICAL_BOSSA_RELATIVE_PATH.as_posix()}"
TOOLCHAIN_ROOT_ENV = "EVOLVER_FIRMWARE_TOOLCHAIN_ROOT"


@dataclass(frozen=True)
class _ArduinoToolchain:
    cli: Path
    data_dir: Path
    config_file: Path
    provenance: dict

    def environment(self) -> dict[str, str]:
        """Return the official Arduino CLI directory environment.

        ``ARDUINO_DIRECTORIES_DATA`` is the documented configuration
        environment variable.  Keep ``ARDUINO_DATA_DIR`` as a compatibility
        alias for older packaged CLI builds; both values are release-owned.
        """
        return {
            **os.environ,
            "ARDUINO_DIRECTORIES_DATA": str(self.data_dir),
            "ARDUINO_DIRECTORIES_USER": str(self.data_dir.parent / "arduino-libraries"),
            "ARDUINO_CONFIG_FILE": str(self.config_file),
        }


def _toolchain() -> _ArduinoToolchain:
    """Resolve the immutable release-owned Arduino toolchain.

    The three EVOLVER_ARDUINO_* variables are an explicit escape hatch for a
    platform-specific release layout. Otherwise the active release toolchain
    is rooted at EVOLVER_FIRMWARE_TOOLCHAIN_ROOT (or its release-root
    equivalent). No executable is ever discovered through PATH.
    """
    explicit = tuple(os.environ.get(name) for name in (
        "EVOLVER_ARDUINO_CLI", "EVOLVER_ARDUINO_DATA_DIR", "EVOLVER_ARDUINO_CONFIG_FILE"))
    if any(explicit):
        if not all(explicit):
            raise SystemExit("immutable Arduino toolchain requires EVOLVER_ARDUINO_CLI, EVOLVER_ARDUINO_DATA_DIR, and EVOLVER_ARDUINO_CONFIG_FILE")
        cli, data_dir, config_file = (Path(value).resolve() for value in explicit)
    else:
        root_value = os.environ.get(TOOLCHAIN_ROOT_ENV) or os.environ.get("EVOLVER_RELEASE_ROOT")
        if not root_value:
            raise SystemExit("immutable Arduino toolchain is not configured; set EVOLVER_FIRMWARE_TOOLCHAIN_ROOT or EVOLVER_ARDUINO_*")
        root = Path(root_value).resolve()
        # Production releases use firmware-toolchain; accepting toolchain here
        # keeps old staged native artifacts usable when the root is explicit.
        toolchain = root if root.name in {"firmware-toolchain", "toolchain"} else root / "firmware-toolchain"
        if not (toolchain / "bin/arduino-cli").exists() and (root / "toolchain/arduino-cli").exists():
            toolchain = root / "toolchain"
        cli = toolchain / "bin/arduino-cli"
        if not cli.exists():
            cli = toolchain / "arduino-cli"
        data_dir = toolchain / "arduino-data"
        config_file = toolchain / "arduino-cli.yaml"

    if not cli.is_file() or not os.access(cli, os.X_OK):
        raise SystemExit(f"immutable Arduino CLI is missing or not executable: {cli}")
    if not data_dir.is_dir():
        raise SystemExit(f"immutable Arduino data directory is missing: {data_dir}")
    if not config_file.is_file():
        raise SystemExit(f"immutable Arduino config file is missing: {config_file}")

    provenance_candidates = [config_file.parent / "PROVENANCE.json", cli.parent / "PROVENANCE.json"]
    if cli.parent.name == "bin":
        provenance_candidates.append(cli.parent.parent / "PROVENANCE.json")
    provenance_path = next((path for path in provenance_candidates if path.is_file()), None)
    if provenance_path is None:
        raise SystemExit("immutable Arduino toolchain provenance is missing: PROVENANCE.json")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"immutable Arduino toolchain provenance is invalid: {provenance_path}") from error
    cli_metadata = provenance.get("arduino_cli")
    if not isinstance(cli_metadata, dict) or not isinstance(cli_metadata.get("version"), str) or not cli_metadata["version"]:
        raise SystemExit("immutable Arduino toolchain provenance lacks the CLI version")
    return _ArduinoToolchain(cli, data_dir, config_file, provenance)


def source_root() -> Path:
    return Path(os.environ.get("EVOLVER_FIRMWARE_SOURCE", "applications/evolver/firmware/source"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="evolver-firmware")
    parser.add_argument("action", choices=("build", "upload", "verify", "preflight"))
    parser.add_argument("--port")
    parser.add_argument("--physical", action="store_true",
                        help="explicitly authorize a physical upload; CI and dry runs omit this")
    parser.add_argument("--operator", help="required attribution for a physical upload")
    parser.add_argument("--sha256", help="expected artifact SHA-256 for upload verification")
    parser.add_argument("--state-root", default=os.environ.get("EVOLVER_STATE_ROOT", ".evolver"))
    parser.add_argument("--artifact", type=Path, help="binary to verify or upload")
    return parser


def _run_read_only(command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command permitted by firmware preflight; never pass a port or upload action."""
    # Callers inspect returncode so failures can be reported as preflight
    # failures rather than leaking a subprocess traceback.
    return subprocess.run(command, check=False, text=True, capture_output=True, env=env)


def _preflight(toolchain: _ArduinoToolchain) -> int:
    """Prove the installed release resolves its exact root-level BOSSA wrapper."""
    provenance = toolchain.provenance
    bossac = provenance.get("bossac")
    if not isinstance(bossac, dict) or bossac.get("delivery") != "nix-store-export-v1":
        raise SystemExit("preflight requires Nix BOSSA provenance")
    store_root = bossac.get("store_root")
    store_executable = bossac.get("store_executable")
    closure_paths = bossac.get("closure_paths")
    closure_artifact = bossac.get("closure_artifact")
    closure_sha = bossac.get("closure_sha256")
    if not all(isinstance(value, str) for value in (store_root, store_executable, closure_artifact, closure_sha)) or not isinstance(closure_paths, list):
        raise SystemExit("preflight Nix BOSSA provenance is incomplete")
    store_root_path, store_executable_path = Path(store_root), Path(store_executable)
    if not store_root_path.is_dir() or _run_read_only(["nix-store", "--verify-path", str(store_root_path)]).returncode != 0:
        raise SystemExit("preflight Nix BOSSA store root verification failed")
    actual_paths = _run_read_only(["nix-store", "--query", "--requisites", str(store_root_path)]).stdout.splitlines()
    if store_root not in actual_paths or not set(closure_paths).issubset(actual_paths):
        raise SystemExit("preflight Nix BOSSA closure does not match provenance")
    if not store_executable_path.is_file() or not os.access(store_executable_path, os.X_OK):
        raise SystemExit("preflight Nix BOSSA store executable is missing or not executable")
    if hashlib.sha256(store_executable_path.read_bytes()).hexdigest() != bossac.get("store_executable_sha256"):
        raise SystemExit("preflight Nix BOSSA store executable digest mismatch")
    release_root = toolchain.config_file.parent
    if release_root.name == "firmware-toolchain":
        release_root = release_root.parent
    closure_file = toolchain.config_file.parent / closure_artifact.removeprefix("toolchain/")
    if not closure_file.is_file() or hashlib.sha256(closure_file.read_bytes()).hexdigest() != closure_sha:
        raise SystemExit("preflight Nix BOSSA closure artifact digest mismatch")
    gc_root = release_root / "firmware-toolchain/nix-roots/bossac"
    if not gc_root.is_symlink() or gc_root.resolve() != store_root_path:
        raise SystemExit("preflight Nix BOSSA final GC root is missing or points elsewhere")
    if bossac.get("path") != CANONICAL_BOSSA_PROVENANCE_PATH:
        raise SystemExit("preflight BOSSA provenance path is not the canonical Arduino root path")
    expected = toolchain.data_dir / CANONICAL_BOSSA_RELATIVE_PATH
    if not expected.is_file() or not os.access(expected, os.X_OK):
        raise SystemExit(f"preflight root BOSSA wrapper is missing or not executable: {expected}")
    wrapper = expected.read_text(encoding="utf-8")
    expected_wrapper = f"#!/bin/sh\nexec {store_executable} \"$@\"\n"
    if wrapper != expected_wrapper or hashlib.sha256(expected.read_bytes()).hexdigest() != bossac.get("wrapper_sha256"):
        raise SystemExit("preflight root BOSSA wrapper is not the deterministic release wrapper")
    platform = next(toolchain.data_dir.glob("packages/SparkFun/hardware/samd/*/platform.txt"), None)
    if platform is None or '"{path}/{cmd}"' not in platform.read_text(encoding="utf-8"):
        raise SystemExit("preflight SparkFun platform upload pattern is not canonical")
    config_dump = _run_read_only([str(toolchain.cli), "--config-file", str(toolchain.config_file), "config", "dump", "--verbose"], env=toolchain.environment())
    if config_dump.returncode != 0:
        raise SystemExit("preflight Arduino configuration dump failed")
    config_values = {}
    for line in config_dump.stdout.splitlines():
        stripped = line.strip()
        for key in ("data", "user", "downloads"):
            if stripped.startswith(f"{key}:"):
                config_values[key] = stripped.split(":", 1)[1].strip().strip('"')
    expected_config = {"data": str(toolchain.data_dir), "user": str(toolchain.data_dir.parent / "arduino-libraries"), "downloads": str(toolchain.data_dir / "staging")}
    if any(config_values.get(key) != value for key, value in expected_config.items()) or any("." + release_root.name + ".new" in value for value in config_values.values()):
        raise SystemExit("preflight Arduino configuration does not use final release paths")
    properties = _run_read_only([str(toolchain.cli), "--config-file", str(toolchain.config_file), "board", "details",
                                 "--fqbn", FQBN, "--show-properties=expanded"], env=toolchain.environment()).stdout
    props = dict(line.split("=", 1) for line in properties.splitlines() if "=" in line)
    selected_dir = props.get("tools.bossac.path")
    selected_cmd = props.get("tools.bossac.cmd")
    actual = Path(selected_dir or "") / (selected_cmd or "")
    if selected_dir != str(expected.parent) or selected_cmd != "bossac" or actual != expected:
        raise SystemExit("preflight Arduino expanded BOSSA resolution does not select the release root wrapper")
    # BOSSA 1.7.0-arduino3 has no version option: its help path prints the
    # banner and exits with getopt's usage status.  Probe that non-mutating
    # path and require the expected banner rather than treating any failure as
    # liveness evidence.
    liveness = _run_read_only([str(expected), "--help"])
    if liveness.returncode not in (0, 1) or "Basic Open Source SAM-BA Application (BOSSA)" not in (liveness.stdout + liveness.stderr):
        raise SystemExit("preflight BOSSA wrapper liveness check failed")
    print(f"ARDUINO_BOSSAC_TOOL_DIR={selected_dir}")
    print(f"ARDUINO_BOSSAC_CMD={selected_cmd}")
    print(f"ARDUINO_BOSSAC_EXECUTABLE={actual}")
    print(f"STORE_BOSSAC_EXECUTABLE={store_executable}")
    print(f"GC_ROOT={gc_root}")
    print("CLOSURE_STATUS=verified")
    print(properties, end="")
    return 0


def _artifact(args: argparse.Namespace) -> Path:
    if args.artifact:
        return args.artifact
    return Path(os.environ.get("EVOLVER_FIRMWARE_ARTIFACT", "firmware.bin"))


def _expected_artifact_digest(args: argparse.Namespace) -> str | None:
    if args.sha256:
        return args.sha256.lower()
    value = os.environ.get("EVOLVER_FIRMWARE_SHA256")
    if value:
        return value.lower()
    digest_file = os.environ.get("EVOLVER_FIRMWARE_SHA256_FILE")
    if digest_file:
        path = Path(digest_file)
        if path.is_file():
            return path.read_text(encoding="utf-8").strip().lower()
    return None


@contextmanager
def _hardware_ownership(state_root: str):
    """Flash maintenance shares the same exclusive ownership lock as hardware service."""
    path = Path(state_root) / "hardware-service.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SystemExit("hardware service owns serial; stop it before firmware maintenance") from error
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.action == "preflight":
        return _preflight(_toolchain())
    if args.action == "verify":
        artifact = _artifact(args)
        if not artifact.is_file():
            print(f"firmware artifact not found: {artifact}")
            return 2
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        expected_digest = _expected_artifact_digest(args)
        if not expected_digest:
            print("verify requires the release firmware SHA-256")
            return 2
        if digest != expected_digest:
            print(f"firmware SHA-256 mismatch: expected {expected_digest}, got {digest}")
            return 2
        print(digest)
        return 0
    if args.action == "upload":
        if not args.physical:
            raise SystemExit("upload requires --physical and an explicit --port")
        if not args.port:
            raise SystemExit("upload requires --physical and an explicit --port")
        if not args.operator:
            raise SystemExit("upload requires --operator attribution")
        toolchain = _toolchain()
        artifact = _artifact(args)
        if not artifact.is_file(): raise SystemExit(f"firmware artifact not found: {artifact}")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        expected_digest = _expected_artifact_digest(args)
        if not expected_digest:
            raise SystemExit("upload requires the release firmware SHA-256")
        if digest != expected_digest: raise SystemExit("firmware SHA-256 mismatch")
    if args.action != "upload":
        toolchain = _toolchain()
    sketch = source_root() / "SAMD21" / "MINEVOLVER"
    libraries = source_root() / "libraries"
    if args.action != "upload" and not (sketch / "MINEVOLVER.ino").is_file():
        raise SystemExit(f"vendored firmware sketch is missing: {sketch}")
    command = [str(toolchain.cli), "compile", "--fqbn", FQBN, "--libraries", str(libraries)]
    if args.action == "upload":
        # A release upload consumes the already SHA-checked immutable artifact;
        # it does not silently rebuild a different sketch.
        command = [str(toolchain.cli), "upload", "--fqbn", FQBN, "--input-file", str(artifact), "--port", args.port]
    else:
        command.append(str(sketch))
    with _hardware_ownership(args.state_root) if args.action == "upload" else _null_context():
        subprocess.run(command, check=True, env=toolchain.environment())
    if args.action == "upload":
        print(f"firmware upload complete; sha256={digest}; operator={args.operator}; verification=protocol_pending")
    return 0


@contextmanager
def _null_context():
    yield


if __name__ == "__main__":
    raise SystemExit(main())
