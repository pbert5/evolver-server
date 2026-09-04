"""Host inspection and systemd unit rendering for explicit controller bootstrap."""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .store import EdgeStore


OWNED_UNITS = ("evolver-hardware.service", "evolver-controller.service")
OWNED_LINKS = ("evolverctl", "evolver-controller", "evolver-hardware")
DEFAULT_NATIVE_ROOT = Path("/opt/evolver-controller")
DEFAULT_BIN_ROOT = Path("/usr/local/bin")
DEFAULT_SYSTEMD_ROOT = Path("/etc/systemd/system")
DEFAULT_SYSTEMD_CONTROL_ROOT = Path("/etc/systemd/system.control")
DEFAULT_CACHE_ROOT = Path("/var/cache/evolver-controller")


@dataclass(frozen=True)
class InstallationStatus:
    backend: str
    architecture: str
    systemd: bool
    controller: dict | None
    binding: dict | None
    active_runs: list[dict]
    installed_release: str | None = None
    runtime_installed: bool = False
    durable_state_present: bool = False
    identity_present: bool = False
    binding_present: bool = False


def detect_backend() -> str:
    if shutil.which("nix"):
        return "nix"
    # OCI images are not an installation backend yet.  Pulling one does not
    # atomically replace both supervised services, perform a health check, or
    # restore the prior image on failure.  Do not make a host with podman look
    # supported until those lifecycle semantics exist.
    return "native"


def persistent_systemd_root() -> Path:
    """Return a writable, persistent systemd unit directory.

    NixOS deliberately makes /etc/systemd/system a symlink into /nix/store.
    systemd 260 searches /etc/systemd/system.control before that immutable
    directory; it is the supported host-local override location.  A runtime
    directory is never an acceptable installer fallback.
    """
    configured = os.environ.get("EVOLVER_SYSTEMD_UNIT_DIR")
    if configured:
        root = Path(configured)
        if str(root).startswith("/run/") or root == Path("/run"):
            raise RuntimeError("EVOLVER_SYSTEMD_UNIT_DIR must be persistent, not under /run")
        return root
    if os.access(DEFAULT_SYSTEMD_ROOT, os.W_OK):
        return DEFAULT_SYSTEMD_ROOT
    control = DEFAULT_SYSTEMD_CONTROL_ROOT
    if control.exists() or os.access(control.parent, os.W_OK):
        return control
    raise RuntimeError("no writable persistent systemd unit directory is available")


def _is_systemd_control_root(root: Path) -> bool:
    return root.resolve() == DEFAULT_SYSTEMD_CONTROL_ROOT or root.name == "system.control"


def _control_dropins(root: Path) -> dict[Path, str]:
    return {
        root / "multi-user.target.d" / "evolver-controller.conf":
        "[Unit]\nWants=evolver-controller.service\n",
        root / "multi-user.target.d" / "evolver-hardware.conf":
        "[Unit]\nWants=evolver-hardware.service\n",
    }


def inspect_installation(state_root: str | Path, *, native_root: str | Path = DEFAULT_NATIVE_ROOT) -> InstallationStatus:
    root = Path(state_root)
    native = Path(native_root)
    runtime_installed = (native / "current/bin/evolverctl").is_file() and os.access(native / "current/bin/evolverctl", os.X_OK)
    durable_state_present = (root / "edge.sqlite3").exists()
    if not (root / "edge.sqlite3").exists():
        return InstallationStatus(detect_backend(), platform.machine(), Path("/run/systemd/system").exists(), None, None, [], None,
                                   runtime_installed, False, False, False)
    # Inspect without calling EdgeStore.identity(), which would manufacture an
    # identity in a partially-created durable state directory.
    with sqlite3.connect(root / "edge.sqlite3") as connection:
        identity_row = connection.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
        binding_row = connection.execute("SELECT * FROM binding WHERE singleton=1").fetchone()
        binding_columns = [column[1] for column in connection.execute("PRAGMA table_info(binding)")]
        identity = json.loads(identity_row[0]) if identity_row else None
        binding = dict(zip(binding_columns, binding_row)) if binding_row else None
    with EdgeStore(root) as store:
        return InstallationStatus(detect_backend(), platform.machine(), Path("/run/systemd/system").exists(),
                                  identity, binding,
                                  [run for run in store.list_runs() if run["state"] in {"running", "paused", "stopping"}],
                                  store.meta("controller_software_release"), runtime_installed,
                                  durable_state_present, identity is not None, binding is not None)


def status_json(state_root: str | Path) -> dict:
    return asdict(inspect_installation(state_root))


def ownership_inventory(*, native_root: str | Path = DEFAULT_NATIVE_ROOT,
                        bin_root: str | Path = DEFAULT_BIN_ROOT,
                        systemd_root: str | Path = DEFAULT_SYSTEMD_ROOT,
                        cache_root: str | Path = DEFAULT_CACHE_ROOT,
                        state_root: str | Path = "/var/lib/evolver-controller") -> dict:
    """The complete filesystem/process ownership boundary of this installer.

    Firmware and durable state are listed separately because neither is
    removed by ordinary uninstall.  This inventory is also useful to package
    maintainers when adding a new installer-owned path.
    """
    native = Path(native_root)
    return {
        "systemd_units": [str(Path(systemd_root) / unit) for unit in OWNED_UNITS],
        "systemd_boot_dropins": [str(Path(systemd_root) / "multi-user.target.d" / f"{unit[:-8]}.conf") for unit in OWNED_UNITS],
        "systemd_environment_files": [],
        "users_groups": [],
        "executables": [str(Path(bin_root) / link) for link in OWNED_LINKS],
        "release_root": str(native / "releases"),
        "current_symlink": str(native / "current"),
        "previous_symlink": str(native / "previous"),
        "configuration_paths": [],
        "cache_paths": [str(cache_root)],
        "durable_state": str(state_root),
        "logs": ["/var/log/evolver-controller"],
        "firmware_artifacts": str(Path(state_root) / "firmware"),
        "cli_wrappers": [str(Path(bin_root) / link) for link in OWNED_LINKS],
    }


def _active_runs(state_root: Path) -> list[dict]:
    if not (state_root / "edge.sqlite3").exists():
        return []
    with EdgeStore(state_root) as store:
        return [run for run in store.list_runs() if run["state"] in {"running", "paused", "stopping"}]


def _safe_owned_path(path: Path, *, kind: str) -> Path:
    resolved = path.resolve()
    if resolved in {Path("/"), Path("/var"), Path("/opt"), Path("/etc"), Path("/usr"), Path("/tmp")}:
        raise ValueError(f"refusing unsafe {kind} path: {path}")
    return resolved


def _run_systemctl(args: list[str], runner: Callable[..., object] | None = None) -> None:
    if runner is None:
        # Unit lifecycle is an optional host integration. Tests and injected
        # temporary roots must never contact a host systemd instance.
        return
    runner(["systemctl", *args], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _audit(state_root: Path, action: str, *, operator: str | None, purge: bool) -> None:
    state_root.mkdir(parents=True, exist_ok=True)
    with (state_root / "lifecycle-audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"action": action, "operator": operator or "unspecified",
                                 "purge": purge, "software_only": not purge}, sort_keys=True) + "\n")


def uninstall_installation(state_root: str | Path, *, purge: bool = False,
                           confirm: bool = False, force_active: bool = False,
                           operator: str | None = None, native_root: str | Path = DEFAULT_NATIVE_ROOT,
                           bin_root: str | Path = DEFAULT_BIN_ROOT,
                           systemd_root: str | Path | None = None,
                           cache_root: str | Path = DEFAULT_CACHE_ROOT,
                           runner: Callable[..., object] | None = None) -> dict:
    """Remove only installer-owned software, optionally clearing local state.

    ``runner`` and roots are deliberately injectable so purge tests cannot
    touch a real controller.  No hardware command is issued here.
    """
    root = _safe_owned_path(Path(state_root), kind="state")
    native = _safe_owned_path(Path(native_root), kind="native")
    cache = _safe_owned_path(Path(cache_root), kind="cache")
    systemd = (Path(systemd_root) if systemd_root is not None else persistent_systemd_root()).resolve()
    links = [Path(bin_root).resolve() / name for name in OWNED_LINKS]
    active = _active_runs(root)
    if active and not force_active:
        ids = ", ".join(run["id"] for run in active)
        raise RuntimeError(f"active/non-terminal run(s) exist ({ids}); stop or explicitly override with --force-active")
    if purge and not confirm:
        raise ValueError("--purge requires explicit confirmation (--yes in noninteractive automation)")
    if purge and not force_active and active:
        raise RuntimeError("purge requires --force-active while an active/non-terminal run exists")

    _audit(root, "uninstall_requested", operator=operator, purge=purge)
    for unit in OWNED_UNITS:
        _run_systemctl(["disable", "--now", unit], runner)
    for unit in OWNED_UNITS:
        (systemd / unit).unlink(missing_ok=True)
    for dropin in _control_dropins(systemd):
        dropin.unlink(missing_ok=True)
    for link in links:
        if link.is_symlink() and link.resolve().is_relative_to(native):
            link.unlink()
    # Only the installer-owned release tree and cache are removed.  The
    # durable state root, including its firmware directory, is never part of
    # the software tree.
    if (native / ".evolver-owned").is_file() and (native / "releases").exists():
        shutil.rmtree(native / "releases")
        (native / ".evolver-owned").unlink()
    for link in (native / "current", native / "previous"):
        link.unlink(missing_ok=True)
    if (cache / ".evolver-owned").is_file():
        shutil.rmtree(cache)
    _run_systemctl(["daemon-reload"], runner)
    removed = {"units": [str(systemd / unit) for unit in OWNED_UNITS],
               "executables": [str(link) for link in links], "native_releases": str(native / "releases"),
               "cache": str(cache)}
    if purge:
        _audit(root, "purge_requested", operator=operator, purge=True)
        # Refuse to treat an arbitrary directory as controller state.  A
        # marker database is required, and only its contents are removed.
        if not (root / "edge.sqlite3").exists():
            raise ValueError(f"refusing purge: {root} is not an eVOLVER state directory")
        for child in root.iterdir():
            if child.name == "firmware":
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        removed["purged_state"] = str(root)
    return {"action": "purged" if purge else "uninstalled", "preserved_state": str(root),
            "active_runs_overridden": [run["id"] for run in active] if force_active else [], "removed": removed}


def repair_installation(state_root: str | Path, *, native_root: str | Path = DEFAULT_NATIVE_ROOT,
                        bin_root: str | Path = DEFAULT_BIN_ROOT,
                        systemd_root: str | Path | None = None,
                        runner: Callable[..., object] | None = None) -> dict:
    """Restore service definitions and links from the existing current release."""
    root = _safe_owned_path(Path(state_root), kind="state")
    native = _safe_owned_path(Path(native_root), kind="native")
    current = native / "current"
    if not current.is_symlink() or not current.resolve().is_dir():
        raise RuntimeError("repair requires an installed current release; run the server-hosted installer")
    controller = current / "bin/evolver-controller"
    hardware = current / "bin/evolver-hardware"
    ctl = current / "bin/evolverctl"
    if not all(item.is_file() and os.access(item, os.X_OK) for item in (controller, hardware, ctl)):
        raise RuntimeError("current release is incomplete; reinstall a verified release")
    links = {"evolverctl": ctl, "evolver-controller": controller, "evolver-hardware": hardware}
    binaries = Path(bin_root).resolve(); binaries.mkdir(parents=True, exist_ok=True)
    for name, target in links.items():
        link = binaries / name
        if link.exists() and not link.is_symlink():
            raise RuntimeError(f"refusing to replace non-installer path: {link}")
        link.unlink(missing_ok=True)
        link.symlink_to(target)
    # An explicitly supplied unit root is used for temporary/test roots or an
    # externally managed systemd installation.  Keep that distinction in the
    # result without probing or contacting the host systemd instance.
    systemd_lifecycle = "temporary_or_external" if systemd_root is not None else "systemd"
    systemd = (Path(systemd_root) if systemd_root is not None else persistent_systemd_root()).resolve(); systemd.mkdir(parents=True, exist_ok=True)
    control = _is_systemd_control_root(systemd)
    (systemd / OWNED_UNITS[0]).write_text(hardware_systemd_unit(executable=str(hardware), state_root=str(root), install_config=not control), encoding="utf-8")
    (systemd / OWNED_UNITS[1]).write_text(systemd_unit(executable=str(controller), state_root=str(root), install_config=not control), encoding="utf-8")
    if control:
        for dropin, content in _control_dropins(systemd).items():
            dropin.parent.mkdir(parents=True, exist_ok=True)
            dropin.write_text(content, encoding="utf-8")
    _run_systemctl(["daemon-reload"], runner)
    _run_systemctl(["enable", "--now", *OWNED_UNITS], runner)
    return {"action": "repaired", "release": str(current.resolve()), "preserved_state": str(root),
            "systemd_lifecycle": systemd_lifecycle}


def _toolchain_environment(toolchain_root: str | None) -> str:
    if not toolchain_root:
        return ""
    root = Path(toolchain_root)
    return (f'Environment="PATH={root / "bin"}:/usr/local/bin:/usr/bin:/bin"\n'
            f'Environment="EVOLVER_FIRMWARE_TOOLCHAIN_ROOT={root}"\n'
            f'Environment="ARDUINO_DIRECTORIES_DATA={root / "arduino-data"}"\n'
            f'Environment="ARDUINO_DIRECTORIES_USER={root / "arduino-libraries"}"\n'
            f'Environment="ARDUINO_CONFIG_FILE={root / "arduino-cli.yaml"}"\n'
            f'Environment="EVOLVER_FIRMWARE_SHA256_FILE={root.parent / "firmware" / "sha256"}"\n'
            f'Environment="EVOLVER_FIRMWARE_ARTIFACT={root.parent / "firmware" / "firmware.bin"}"\n')


def systemd_unit(*, executable: str = "/usr/local/bin/evolver-controller", state_directory: str = "evolver-controller",
                 state_root: str | None = None, install_config: bool = True,
                 firmware_toolchain_root: str | None = None) -> str:
    """Render a conservative unit: state survives repair/update and reboot."""
    return f"""[Unit]
Description=eVOLVER edge controller
After=network-online.target evolver-hardware.service
Wants=network-online.target evolver-hardware.service

[Service]
Type=simple
ExecStart={executable} --state-root {state_root or f'/var/lib/{state_directory}'}
Restart=on-failure
RestartSec=5s
StateDirectory={state_directory}
StateDirectoryMode=0750
UMask=0077
NoNewPrivileges=true
{_toolchain_environment(firmware_toolchain_root)}

{('[Install]\nWantedBy=multi-user.target\n' if install_config else '')}"""


def hardware_systemd_unit(*, executable: str = "/usr/local/bin/evolver-hardware", state_directory: str = "evolver-controller",
                          state_root: str | None = None, install_config: bool = True,
                          firmware_toolchain_root: str | None = None) -> str:
    """The read-only serial owner is independently supervised by systemd."""
    return f"""[Unit]
Description=eVOLVER read-only hardware service
After=network-online.target
Wants=network-online.target
Before=evolver-controller.service

[Service]
Type=simple
ExecStart={executable} --state-root {state_root or f'/var/lib/{state_directory}'}
Restart=on-failure
RestartSec=5s
StateDirectory={state_directory}
StateDirectoryMode=0750
UMask=0077
SupplementaryGroups=dialout
NoNewPrivileges=true
{_toolchain_environment(firmware_toolchain_root)}

{('[Install]\nWantedBy=multi-user.target\n' if install_config else '')}"""


def installer_script(*, default_server_url: str, source_revision: str = "82dfdb74b85e47dbcb4cf3f15bfb3281376ca624",
                     release: str | None = None, manifest_sha256: str | None = None,
                     artifact_metadata: dict[str, dict[str, object]] | None = None,
                     firmware_metadata: dict[str, object] | None = None) -> str:
    """Return the `/install/evolver` shell payload for a particular WebUI.

    The HTTP handler supplies its own origin as ``default_server_url``; this
    avoids trusting a mutable DNS default on the controller.  The script never
    prints the enrollment token and its repair/update modes intentionally leave
    ``EVOLVER_STATE_ROOT`` intact.
    """
    parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(default_server_url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("installer default server must be an HTTP(S) origin")
    if not source_revision or any(char not in "0123456789abcdef" for char in source_revision.lower()):
        raise ValueError("installer source revision must be an immutable hexadecimal git revision")
    if release is not None and (not release or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for char in release)):
        raise ValueError("installer release must be a simple immutable release identifier")
    if manifest_sha256 is not None and (len(manifest_sha256) != 64 or any(char not in "0123456789abcdef" for char in manifest_sha256.lower())):
        raise ValueError("installer manifest must have an immutable SHA-256 digest")
    manifest_path = f"/releases/evolver/{release}/manifest.json" if release else "/releases/evolver-controller.json"
    # A configured manifest version is the native installation identity.  The
    # revision remains a mandatory provenance check, but using it as the
    # directory name made it impossible for an operator to reason about the
    # installed/previous release during repair and rollback.
    release_id = release or source_revision
    bootstrap_rows = []
    for target, entry in sorted((artifact_metadata or {}).items()):
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str) or not isinstance(entry.get("sha256"), str):
            continue
        bootstrap_rows.append(f'''    {target}) ARTIFACT_URL="{entry["url"]}"; ARTIFACT_SHA256="{entry["sha256"].lower()}" ;;''')
    bootstrap_table = "\\n".join(bootstrap_rows)
    firmware_url = firmware_metadata.get("url", "") if isinstance(firmware_metadata, dict) else ""
    firmware_sha = firmware_metadata.get("sha256", "") if isinstance(firmware_metadata, dict) else ""
    firmware_version = firmware_metadata.get("version", "unknown") if isinstance(firmware_metadata, dict) else "unknown"
    return f'''#!/bin/sh
set -eu
set +x
SERVER_URL="{default_server_url.rstrip('/')}"
STATE_ROOT="${{EVOLVER_STATE_ROOT:-/var/lib/evolver-controller}}"
EVOLVER_DEVELOPER_MODE="${{EVOLVER_DEVELOPER_MODE:-false}}"
EVOLVER_NIX_INSTALL_REF="${{EVOLVER_NIX_INSTALL_REF:-server-release}}"
# EVOLVER_DEVELOPER_MODE=true is intentionally a developer-only setting; this
  # production installer never uses it to select an external source.
TOKEN=""
MODE="install"
OPERATION=""
CONFIRM_FORCED_ADOPTION=false
SOURCE_REVISION="{source_revision}"
RELEASE_ID="{release_id}"
EXPECTED_MANIFEST_SHA256="{manifest_sha256 or ''}"
NATIVE_ROOT="${{EVOLVER_NATIVE_ROOT:-/opt/evolver-controller}}"
FIRMWARE_ROOT="${{EVOLVER_FIRMWARE_ROOT:-/var/lib/evolver-controller/firmware}}"
RELEASE_MANIFEST_URL="${{EVOLVER_RELEASE_MANIFEST_URL:-$SERVER_URL{manifest_path}}}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --token) TOKEN="${{2:?--token requires a value}}"; shift 2 ;;
    --server) SERVER_URL="${{2:?--server requires a value}}"; shift 2 ;;
    --mode) MODE="${{2:?--mode requires a value}}"; shift 2 ;;
    --operation) OPERATION="${{2:?--operation requires a value}}"; shift 2 ;;
    --state-root) STATE_ROOT="${{2:?--state-root requires a value}}"; shift 2 ;;
    --confirm-forced-adoption) CONFIRM_FORCED_ADOPTION=true; shift ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done
case "$MODE" in install|repair|update|clean-reinstall|re-enroll|handoff|recover|export-state|factory-reset) ;; *) echo "invalid mode" >&2; exit 64;; esac
case "$SERVER_URL" in https://*|http://*) ;; *) echo "--server must be an HTTP(S) URL" >&2; exit 64;; esac
case "$SERVER_URL" in *[!A-Za-z0-9./:_-]*|*//*//* ) echo "--server contains unsupported characters" >&2; exit 64 ;; esac
[ "$(id -u)" -eq 0 ] || {{ echo "run the installer as root (for example: sudo sh)" >&2; exit 77; }}
[ -d /run/systemd/system ] || {{ echo "systemd is required for a persistent controller installation" >&2; exit 69; }}

# Resolve lifecycle intent before downloading or switching a release.  When
# this payload is piped from curl, prompts are read from /dev/tty so the
# script stream is never consumed as operator input.
CURRENT_CTL=""
if [ -x "$NATIVE_ROOT/current/bin/evolverctl" ]; then CURRENT_CTL="$NATIVE_ROOT/current/bin/evolverctl"; fi
TARGET_CTL=""
if [ -z "$OPERATION" ]; then
  case "$MODE" in
    install) OPERATION="" ;;
    repair) OPERATION=repair ;;
    update) OPERATION=update ;;
    handoff) OPERATION=handoff ;;
    recover) OPERATION=forced-adoption ;;
    export-state) OPERATION=export-state ;;
    factory-reset) OPERATION=factory-reset ;;
    re-enroll) OPERATION=install ;;
  esac
fi
case "$OPERATION" in
  install) MODE=install ;;
  update) MODE=update ;;
  clean-reinstall) MODE=clean-reinstall ;;
  repair) MODE=repair ;;
  uninstall) MODE=uninstall ;;
  handoff) MODE=handoff ;;
  forced-adoption) MODE=recover ;;
  export-state) MODE=export-state ;;
  factory-reset) MODE=factory-reset ;;
  '') : ;;
  *) echo "invalid operation: $OPERATION" >&2; exit 64 ;;
esac

# Bootstrap inspection is deliberately limited to POSIX shell and filesystem
# checks. The release owns JSON, SQLite, and lifecycle inspection after the
# immutable artifact handoff; a host JSON utility is not a prerequisite.
STAGE="$(mktemp -d)"
RELEASE_ROOT=""
RELEASE_PUBLISHED=false
INSTALL_COMMITTED=false
PREVIOUS_RELEASE=""
cleanup_install() {{
  cleanup_status=$?
  if [ "${{RELEASE_PUBLISHED:-false}}" = true ] && [ "${{INSTALL_COMMITTED:-false}}" != true ]; then
    # Publication happens before enrollment.  If the transaction stops after
    # publication, first get the candidate out of current (without touching a
    # valid prior release), then remove only this transaction's release ID.
    if [ -L "$NATIVE_ROOT/current" ] && [ "$(readlink -f "$NATIVE_ROOT/current" || true)" = "$RELEASE_ROOT" ]; then
      if [ -n "$PREVIOUS_RELEASE" ] && [ -d "$PREVIOUS_RELEASE" ]; then
        rm -f "$NATIVE_ROOT/.current.cleanup"
        ln -s "$PREVIOUS_RELEASE" "$NATIVE_ROOT/.current.cleanup"
        mv -Tf "$NATIVE_ROOT/.current.cleanup" "$NATIVE_ROOT/current"
      else
        rm -f "$NATIVE_ROOT/current"
      fi
    fi
    if [ -n "$RELEASE_ROOT" ] && [ "$(readlink -f "$NATIVE_ROOT/current" || true)" != "$RELEASE_ROOT" ]; then
      rm -rf "$RELEASE_ROOT"
    fi
  fi
  rm -rf "$STAGE"
  trap - EXIT HUP INT TERM
  exit "$cleanup_status"
}}
trap cleanup_install EXIT HUP INT TERM
CURRENT_STATE_FILE="$STAGE/current-state.json"
DURABLE_STATE_PRESENT=false
[ -f "$STATE_ROOT/edge.sqlite3" ] && DURABLE_STATE_PRESENT=true
RUNTIME_INSTALLED=false
[ -n "$CURRENT_CTL" ] && RUNTIME_INSTALLED=true
cat > "$CURRENT_STATE_FILE" <<EOF
{{"controller":null,"binding":null,"active_runs":[],"installed_release":null,"runtime_installed":$RUNTIME_INSTALLED,"durable_state_present":$DURABLE_STATE_PRESENT,"identity_present":false,"binding_present":false}}
EOF
if [ -z "$OPERATION" ] && [ -n "$CURRENT_CTL" -o "$DURABLE_STATE_PRESENT" = true ]; then
  if [ ! -r /dev/tty ]; then
    echo "Existing controller state detected; rerun with an explicit --operation (for example --operation clean-reinstall, handoff, or forced-adoption)." >&2
    exit 64
  fi
  echo "eVOLVER Controller Setup" > /dev/tty
  if [ -n "$CURRENT_CTL" ]; then
    echo "Existing controller detected. Choose a lifecycle operation:" > /dev/tty
    echo "[1] Move this controller to this server" > /dev/tty
    echo "[2] Update controller software" > /dev/tty
    echo "[3] Repair current installation" > /dev/tty
    echo "[4] Clean reinstall software" > /dev/tty
    echo "[5] Remove controller software" > /dev/tty
    echo "[6] Advanced recovery / factory reset" > /dev/tty
    echo "[7] Cancel" > /dev/tty
  else
    echo "Existing controller state detected; controller software is not currently installed." > /dev/tty
    echo "[1] Move/recover controller to this server" > /dev/tty
    echo "[2] Clean reinstall software" > /dev/tty
    echo "[3] Advanced recovery / factory reset" > /dev/tty
    echo "[4] Cancel" > /dev/tty
  fi
  printf 'Choice: ' > /dev/tty
  IFS= read -r CHOICE < /dev/tty || {{ echo "No lifecycle choice supplied; nothing was changed." >&2; exit 64; }}
  if [ -n "$CURRENT_CTL" ]; then
    case "$CHOICE" in 1) OPERATION=handoff ;; 2) OPERATION=update ;; 3) OPERATION=repair ;; 4) OPERATION=clean-reinstall ;; 5) OPERATION=uninstall ;; 6) OPERATION=factory-reset ;; 7) echo "Cancelled; no controller state was changed."; exit 0 ;; *) echo "Invalid lifecycle choice; no controller state was changed." >&2; exit 64 ;; esac
  else
    case "$CHOICE" in 1) OPERATION=handoff ;; 2) OPERATION=clean-reinstall ;; 3) OPERATION=factory-reset ;; 4) echo "Cancelled; no controller state was changed."; exit 0 ;; *) echo "Invalid lifecycle choice; no controller state was changed." >&2; exit 64 ;; esac
  fi
fi
case "$OPERATION" in
  install) MODE=install ;; update) MODE=update ;; clean-reinstall) MODE=clean-reinstall ;; repair) MODE=repair ;;
  uninstall) MODE=uninstall ;; handoff) MODE=handoff ;; forced-adoption) MODE=recover ;;
  export-state) MODE=export-state ;; factory-reset) MODE=factory-reset ;; '') : ;;
  *) echo "invalid operation: $OPERATION" >&2; exit 64 ;;
esac
check_existing_plan() {{
  case "$OPERATION" in
    install|repair|update|clean-reinstall|uninstall|handoff|forced-adoption|factory-reset) : ;;
    *) return 0 ;;
  esac
  [ -n "$TARGET_CTL" ] || return 0
  PLAN_ARGS="--operation $OPERATION"
  case "$OPERATION" in
    update|clean-reinstall) PLAN_ARGS="$PLAN_ARGS --release $RELEASE_ID" ;;
    handoff|forced-adoption) PLAN_ARGS="$PLAN_ARGS --server $SERVER_URL" ;;
  esac
  if [ "$OPERATION" = forced-adoption ] && [ "$CONFIRM_FORCED_ADOPTION" = true ]; then
    PLAN_ARGS="$PLAN_ARGS --confirmed"
  fi
  # The target release owns the pure planner; the old runtime only supplied
  # the explicit inspection snapshot above.
  # Word splitting is limited to the fixed arguments assembled above.
  # shellcheck disable=SC2086
  "$TARGET_CTL" --state-root "$STATE_ROOT" lifecycle-plan --current-state "$CURRENT_STATE_FILE" $PLAN_ARGS || {{
    echo "Lifecycle plan rejected; no controller software or binding was changed." >&2
    exit 2
  }}
}}
if [ "$MODE" = repair ] || [ "$MODE" = uninstall ]; then
  [ -n "$CURRENT_CTL" ] || {{ echo "$MODE requires an installed controller runtime" >&2; exit 64; }}
  if [ "$MODE" = repair ]; then exec "$CURRENT_CTL" --state-root "$STATE_ROOT" repair; fi
  exec "$CURRENT_CTL" --state-root "$STATE_ROOT" uninstall
fi
if [ "$MODE" = factory-reset ]; then
  echo "Factory reset is an advanced destructive action and is not part of software reinstall. Export recovery state and use a separately confirmed maintenance procedure." >&2
  exit 64
fi
if [ -n "$CURRENT_CTL" ]; then
  EVOLVERCTL="$CURRENT_CTL"
  CONTROLLER="$NATIVE_ROOT/current/bin/evolver-controller"
  HARDWARE="$NATIVE_ROOT/current/bin/evolver-hardware"
fi

install_native() {{
  INSTALL_BACKEND=native
  command -v curl >/dev/null 2>&1 || {{ echo "curl is required for the native installer backend" >&2; exit 69; }}
  command -v sha256sum >/dev/null 2>&1 || {{ echo "sha256sum is required for the native installer backend" >&2; exit 69; }}
  case "$(uname -m)" in x86_64|amd64) ARTIFACT_ARCH=x86_64 ;; aarch64|arm64) ARTIFACT_ARCH=aarch64 ;; *) echo "unsupported native architecture: $(uname -m)" >&2; exit 69 ;; esac
  # The release-owned glibc bundle is also the supported NixOS target here:
  # NixOS supplies the kernel/systemd boundary, while the release owns its
  # userspace interpreter and application libraries.  A Nix-store BOSSA
  # closure is only selected when a future release explicitly publishes the
  # separate nixos target metadata.
  ARTIFACT_RUNTIME=glibc
  ARTIFACT_TARGET="linux-${{ARTIFACT_ARCH}}-${{ARTIFACT_RUNTIME}}"
  ARTIFACT_URL=""
  ARTIFACT_SHA256=""
  case "$ARTIFACT_TARGET" in
{bootstrap_table}
  esac
  FIRMWARE_URL="{firmware_url}"
  FIRMWARE_SHA256="{firmware_sha}"
  FIRMWARE_VERSION="{firmware_version}"
  case "$ARTIFACT_URL" in /*) ARTIFACT_URL="$SERVER_URL$ARTIFACT_URL" ;; esac
  case "$FIRMWARE_URL" in /*) FIRMWARE_URL="$SERVER_URL$FIRMWARE_URL" ;; esac
  [ -n "$ARTIFACT_SHA256" ] || {{ echo "server did not provide verified target metadata" >&2; exit 65; }}
  curl --fail --silent --show-error --location "$RELEASE_MANIFEST_URL" -o "$STAGE/manifest.json"
  if [ -n "$EXPECTED_MANIFEST_SHA256" ]; then
    printf '%s  %s\n' "$EXPECTED_MANIFEST_SHA256" "$STAGE/manifest.json" | sha256sum --check --status || {{ echo "release manifest digest mismatch" >&2; exit 65; }}
  fi
  curl --fail --silent --show-error --location "$ARTIFACT_URL" -o "$STAGE/controller.tar.gz"
  printf '%s  %s\\n' "$ARTIFACT_SHA256" "$STAGE/controller.tar.gz" | sha256sum --check --status || {{ echo "native controller artifact digest mismatch" >&2; exit 65; }}
  case "$FIRMWARE_URL" in /*) FIRMWARE_URL="$SERVER_URL$FIRMWARE_URL" ;; esac
  curl --fail --silent --show-error --location "$FIRMWARE_URL" -o "$STAGE/firmware.bin"
  printf '%s  %s\\n' "$FIRMWARE_SHA256" "$STAGE/firmware.bin" | sha256sum --check --status || {{ echo "firmware artifact digest mismatch" >&2; exit 65; }}
  # The archive carries the interpreter and its already-materialized
  # site-packages.  Use the release-owned interpreter for all subsequent
  # inspection; the target need not provide Python, pip, jq, unzip, or git.
  mkdir -p "$STAGE/controller.tar.gz.validated"
  tar --no-same-owner --no-same-permissions -xzf "$STAGE/controller.tar.gz" -C "$STAGE/controller.tar.gz.validated"
  PYTHON3=""
  for candidate in "$STAGE/controller.tar.gz.validated/python/bin/python" "$STAGE/controller.tar.gz.validated/python/bin/python3"; do
    if [ -x "$candidate" ]; then PYTHON3="$candidate"; break; fi
  done
  [ -n "$PYTHON3" ] || {{ echo "release artifact has no bundled Python runtime" >&2; exit 69; }}
  "$PYTHON3" - "$STAGE/controller.tar.gz" "$STAGE/controller.tar.gz.validated" <<'PY'
import posixpath, sys, tarfile
archive, destination = sys.argv[1], sys.argv[2]
with tarfile.open(archive, "r:gz") as tar:
    seen = set()
    kinds = {{}}
    reserved = {"manifest.json", "firmware.bin", "controller.tar.gz", "artifact.env"}
    for member in tar.getmembers():
        name = member.name
        if not name or name.startswith("/") or "\\x00" in name:
            raise SystemExit("native controller archive has an unsafe member path")
        normalized = posixpath.normpath(name)
        if normalized == "." or normalized == ".." or normalized.startswith("../"):
            raise SystemExit("native controller archive member escapes extraction root")
        if normalized in reserved or normalized.startswith("firmware/"):
            raise SystemExit("native controller archive contains a reserved release path")
        if normalized in seen:
            raise SystemExit("native controller archive contains duplicate members")
        seen.add(normalized)
        if member.isdir():
            kinds[normalized.rstrip("/")] = "dir"
        elif member.isfile():
            kinds[normalized] = "file"
        else:
            raise SystemExit("native controller archive contains links or special files")
    for name, kind in kinds.items():
        parent = posixpath.dirname(name)
        while parent:
            if kinds.get(parent) == "file":
                raise SystemExit("native controller archive contains a file/directory prefix collision")
            parent = posixpath.dirname(parent)
    # The shell extraction above supplies the release-owned interpreter; this
    # pass validates every member before its contents are published.
PY
  # The validator extracts into a private directory only after validation.
  # Move its complete contents into STAGE without allowing archive paths to
  # collide with the manifest or downloaded firmware.
  cp -a "$STAGE/controller.tar.gz.validated/." "$STAGE/"
  PYTHON3="$STAGE/python/bin/python"
  [ -x "$PYTHON3" ] || PYTHON3="$STAGE/python/bin/python3"
  rm -rf "$STAGE/controller.tar.gz.validated"
  "$PYTHON3" - "$STAGE/manifest.json" "$ARTIFACT_TARGET" "$SOURCE_REVISION" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1], encoding="utf-8"))
target, revision = sys.argv[2:]
entry = manifest.get("artifacts", {{}}).get(target, {{}})
if (manifest.get("git_revision") != revision
        or "lifecycle-plan --current-state" not in manifest.get("required_cli_capabilities", [])
        or entry.get("target") != target
        or not entry.get("url") or not entry.get("sha256")
        or not manifest.get("firmware", {{}}).get("url")
        or not manifest.get("firmware", {{}}).get("sha256")):
    raise SystemExit("release manifest is incompatible with this installer lifecycle protocol")
PY
  # The old runtime is consulted only after the immutable artifact handoff.
  if [ -n "$CURRENT_CTL" ]; then
    "$CURRENT_CTL" --state-root "$STATE_ROOT" install-status > "$STAGE/install-status.json" 2>/dev/null || true
    "$PYTHON3" - "$STAGE/install-status.json" "$CURRENT_STATE_FILE" <<'PY'
import json, sys
source, destination = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    state = json.load(stream)
if not isinstance(state, dict):
    raise SystemExit("installed controller returned invalid inspection data")
state["runtime_installed"] = True
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(state, stream, sort_keys=True)
PY
  fi
  # Validate the toolchain against the manifest before placing anything in a
  # release.  The archive is untrusted input; provenance and declared file
  # digests must agree exactly, and all selected inputs remain offline.
  "$PYTHON3" - "$STAGE/manifest.json" "$STAGE" "$ARTIFACT_TARGET" <<'PY'
import hashlib, json, os, sys
from pathlib import Path
manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
stage, target = Path(sys.argv[2]), sys.argv[3]
entry = manifest.get("artifacts", {{}}).get(target, {{}})
metadata = entry.get("firmware_toolchain")
if manifest.get("firmware_toolchain_required") and not isinstance(metadata, dict):
    raise SystemExit("native artifact manifest lacks required firmware toolchain metadata")
if metadata is None:
    raise SystemExit("native artifact lacks firmware toolchain metadata")
if metadata.get("format") != 1 or metadata.get("offline") is not True:
    raise SystemExit("native artifact firmware toolchain is not an offline format-1 bundle")
cli = metadata.get("arduino_cli", {{}})
data = metadata.get("arduino_data", {{}})
libraries = metadata.get("arduino_libraries", {{}})
if not isinstance(cli, dict) or not isinstance(data, dict) or not isinstance(libraries, dict):
    raise SystemExit("native artifact firmware toolchain metadata is incomplete")
cli_path = cli.get("path", "")
data_path = data.get("path", "")
libraries_path = libraries.get("path", "")
if not isinstance(cli_path, str) or not isinstance(data_path, str) or not isinstance(libraries_path, str):
    raise SystemExit("native artifact firmware toolchain paths are invalid")
for declared_path in (cli_path, data_path, libraries_path):
    path = Path(declared_path)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit("native artifact firmware toolchain path escapes the archive")
prefix = "firmware-toolchain/"
legacy_prefix = "toolchain/"
if cli_path.startswith(prefix) and data_path.startswith(prefix) and libraries_path.startswith(prefix):
    source = stage / "firmware-toolchain"
elif cli_path.startswith(legacy_prefix) and data_path.startswith(legacy_prefix):
    source = stage / "toolchain"
else:
    raise SystemExit("native artifact firmware toolchain paths are not release-local")
provenance = source / "PROVENANCE.json"
if not provenance.is_file() or json.loads(provenance.read_text(encoding="utf-8")) != metadata:
    raise SystemExit("native artifact firmware toolchain provenance does not match manifest")
cli_file = stage / cli_path
if not cli_file.is_file() or not os.access(cli_file, os.X_OK):
    raise SystemExit("native artifact firmware toolchain CLI is missing or not executable")
declared = cli.get("sha256")
if not isinstance(declared, str) or hashlib.sha256(cli_file.read_bytes()).hexdigest() != declared.lower():
    raise SystemExit("native artifact firmware toolchain CLI digest mismatch")
data_dir = stage / data_path
libraries_dir = stage / libraries_path
if not data_dir.is_dir() or not libraries_dir.is_dir():
    raise SystemExit("native artifact firmware toolchain data directory is missing")
bossac = metadata.get("bossac", {{}})
bossac_path, bossac_digest = bossac.get("path"), bossac.get("sha256")
if isinstance(bossac_path, str) and isinstance(bossac_digest, str):
    bossac_relative = Path(bossac_path)
    if bossac_relative.is_absolute() or ".." in bossac_relative.parts:
        raise SystemExit("native artifact firmware toolchain BOSSA path escapes the archive")
    bossac_file = stage / bossac_path
    if not bossac_file.is_file() or hashlib.sha256(bossac_file.read_bytes()).hexdigest() != bossac_digest.lower():
        raise SystemExit("native artifact firmware toolchain BOSSA digest mismatch")
if target == "linux-x86_64-nixos":
    if bossac.get("delivery") != "nix-store-export-v1":
        raise SystemExit("NixOS BOSSA requires a complete Nix store export")
    closure_path = bossac.get("closure_artifact")
    closure_digest = bossac.get("closure_sha256")
    store_root = bossac.get("store_root")
    closure_paths = bossac.get("closure_paths")
    if (not isinstance(closure_path, str) or not isinstance(closure_digest, str)
            or not isinstance(store_root, str) or not store_root.startswith("/nix/store/")
            or not isinstance(closure_paths, list) or store_root not in closure_paths):
        raise SystemExit("NixOS BOSSA closure provenance is incomplete")
    closure_file = stage / closure_path
    if not closure_file.is_file() or hashlib.sha256(closure_file.read_bytes()).hexdigest() != closure_digest.lower():
        raise SystemExit("NixOS BOSSA closure digest mismatch")
PY
  RELEASE_ROOT="$NATIVE_ROOT/releases/$RELEASE_ID"
  # Always construct a complete fresh release.  A partial directory from an
  # interrupted install, even one retaining an executable, is never trusted.
  # Keep the candidate outside the installer-owned tree until semantic
  # preflight has passed, so a rejected release leaves no published debris.
  RELEASE_STAGE="$STAGE/release.new"
  rm -rf "$RELEASE_STAGE"
  # The artifact is already a runnable release.  Preserve its interpreter,
  # site-packages, and entrypoint handoff instead of creating a target venv or
  # invoking target pip.
  mkdir -p "$RELEASE_STAGE"
  [ -d "$RELEASE_STAGE" ] || {{ echo "could not create private release staging directory" >&2; exit 65; }}
  cp -a "$STAGE/python" "$STAGE/site-packages" "$STAGE/bin" "$RELEASE_STAGE/"
  TOOLCHAIN_SOURCE="$STAGE/firmware-toolchain"
  [ -d "$TOOLCHAIN_SOURCE" ] || TOOLCHAIN_SOURCE="$STAGE/toolchain"
  [ -d "$TOOLCHAIN_SOURCE" ] || {{ echo "native artifact is missing firmware-toolchain" >&2; exit 65; }}
  {{
    TOOLCHAIN_STAGE="$RELEASE_STAGE/.firmware-toolchain.new"
    install -d -m 0755 "$TOOLCHAIN_STAGE/bin"
    if [ -x "$TOOLCHAIN_SOURCE/bin/arduino-cli" ]; then
      cp -p "$TOOLCHAIN_SOURCE/bin/arduino-cli" "$TOOLCHAIN_STAGE/bin/arduino-cli"
    else
      cp -p "$TOOLCHAIN_SOURCE/arduino-cli" "$TOOLCHAIN_STAGE/bin/arduino-cli"
    fi
    # Artifact configs contain build-host paths.  Generate a release-local
    # config so runtime commands never use a staging or host-global path.
    cat > "$TOOLCHAIN_STAGE/arduino-cli.yaml" <<EOF
directories:
  data: $RELEASE_ROOT/firmware-toolchain/arduino-data
  user: $RELEASE_ROOT/firmware-toolchain/arduino-libraries
  downloads: $RELEASE_ROOT/firmware-toolchain/arduino-data/staging
EOF
    cp -a "$TOOLCHAIN_SOURCE/arduino-data" "$TOOLCHAIN_STAGE/arduino-data"
    if [ -d "$TOOLCHAIN_SOURCE/arduino-libraries" ]; then
      cp -a "$TOOLCHAIN_SOURCE/arduino-libraries" "$TOOLCHAIN_STAGE/arduino-libraries"
    fi
    cp -p "$TOOLCHAIN_SOURCE/PROVENANCE.json" "$TOOLCHAIN_STAGE/PROVENANCE.json"
    if [ "$ARTIFACT_TARGET" = linux-x86_64-nixos ]; then
      install -d -m 0755 "$TOOLCHAIN_STAGE/nix-closures"
      cp -p "$TOOLCHAIN_SOURCE/nix-closures/bossac.closure" "$TOOLCHAIN_STAGE/nix-closures/bossac.closure"
    fi
    chmod 0755 "$TOOLCHAIN_STAGE/bin/arduino-cli"
    mv -T "$TOOLCHAIN_STAGE" "$RELEASE_STAGE/firmware-toolchain"
    if [ "$ARTIFACT_TARGET" = linux-x86_64-nixos ]; then
      BOSSA_ROOT="$($PYTHON3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bossac"]["store_root"])' "$RELEASE_STAGE/firmware-toolchain/PROVENANCE.json")"
      BOSSA_EXECUTABLE="$($PYTHON3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bossac"]["store_executable"])' "$RELEASE_STAGE/firmware-toolchain/PROVENANCE.json")"
      BOSSAC_WRAPPER="$RELEASE_STAGE/firmware-toolchain/arduino-data/packages/arduino/tools/bossac/1.7.0-arduino3/bossac"
      install -d -m 0755 "$(dirname "$BOSSAC_WRAPPER")"
      cat > "$BOSSAC_WRAPPER" <<EOF
#!/bin/sh
exec $BOSSA_EXECUTABLE "\$@"
EOF
      chmod 0755 "$BOSSAC_WRAPPER"
      BOSSAC_LEGACY_WRAPPER="$(dirname "$BOSSAC_WRAPPER")/bin/bossac"
      cp -p "$BOSSAC_WRAPPER" "$BOSSAC_LEGACY_WRAPPER"
      chmod 0755 "$BOSSAC_LEGACY_WRAPPER"
    fi
  }}
  install -d -m 0755 "$RELEASE_STAGE/firmware"
  install -m 0644 "$STAGE/firmware.bin" "$RELEASE_STAGE/firmware/firmware.bin"
  printf '%s\\n' "$FIRMWARE_SHA256" > "$RELEASE_STAGE/firmware/sha256"
  printf '%s\\n' "$FIRMWARE_VERSION" > "$RELEASE_STAGE/firmware/version"
  [ -x "$RELEASE_STAGE/bin/evolverctl" ] && [ -x "$RELEASE_STAGE/bin/evolver-controller" ] && [ -x "$RELEASE_STAGE/bin/evolver-hardware" ] || {{ echo "fresh release is incomplete" >&2; exit 65; }}
  # Release IDs are immutable. Never replace or merge an existing release,
  # even if an interrupted install left a partial directory behind.
  if [ -e "$RELEASE_ROOT" ]; then
    echo "release ID already exists and is immutable" >&2
    exit 65
  fi
  # Probe the target CLI while its staging interpreter still exists.  This is
  # the final semantic gate: a rejected/incompatible target cannot publish a
  # release, switch current, update services, or write controller state.
  TARGET_CTL="$RELEASE_STAGE/bin/evolverctl"
  TARGET_CONTROLLER="$RELEASE_STAGE/bin/evolver-controller"
  TARGET_HARDWARE="$RELEASE_STAGE/bin/evolver-hardware"
  if ! "$TARGET_CTL" --state-root "$STATE_ROOT" lifecycle-plan --current-state "$CURRENT_STATE_FILE" --operation install >"$STAGE/planner-probe.json" 2>"$STAGE/planner-probe.err"; then
    if grep -Eiq 'usage:|unrecognized arguments|invalid choice|unknown command|no such command' "$STAGE/planner-probe.err"; then
      echo "Selected controller release is incompatible with this installer lifecycle protocol. Build/select a newer release before continuing." >&2
      exit 65
    fi
  fi
  mkdir -p "$NATIVE_ROOT/releases"
  install -m 0644 /dev/null "$NATIVE_ROOT/.evolver-owned"
  # Import the complete closure only after semantic preflight succeeds, but
  # before publication.  The GC root below is tied to the final release path.
  if [ "$ARTIFACT_TARGET" = linux-x86_64-nixos ]; then
    nix-store --import < "$RELEASE_STAGE/firmware-toolchain/nix-closures/bossac.closure"
    test -x "$BOSSA_EXECUTABLE"
    test -d "$BOSSA_ROOT"
  fi
  mv -T "$RELEASE_STAGE" "$RELEASE_ROOT"
  RELEASE_PUBLISHED=true
  if [ "$ARTIFACT_TARGET" = linux-x86_64-nixos ]; then
    install -d -m 0755 "$RELEASE_ROOT/firmware-toolchain/nix-roots"
    if ! nix-store --add-root "$RELEASE_ROOT/firmware-toolchain/nix-roots/bossac" --realise "$BOSSA_ROOT"; then
      rm -rf "$RELEASE_ROOT"
      exit 65
    fi
  fi
  PYTHON3="$RELEASE_ROOT/python/bin/python"
  [ -x "$PYTHON3" ] || PYTHON3="$RELEASE_ROOT/python/bin/python3"
  # Keep compatibility with release entrypoints produced by older builders;
  # the current materialized wrappers are root-relative and need no rewrite.
  for executable in "$RELEASE_ROOT/bin/"*; do
    if [ -f "$executable" ] && head -n 1 "$executable" | grep -Fq "$RELEASE_STAGE"; then
      sed -i "1s|$RELEASE_STAGE|$RELEASE_ROOT|" "$executable"
    fi
  done
  TARGET_CTL="$RELEASE_ROOT/bin/evolverctl"
  TARGET_CONTROLLER="$RELEASE_ROOT/bin/evolver-controller"
  TARGET_HARDWARE="$RELEASE_ROOT/bin/evolver-hardware"
}}
install_software() {{
  # Production installation always consumes the server-hosted immutable
  # bundle; a local Nix installation must not turn into a GitHub fetch.
  install_native
  [ -x "$TARGET_CTL" ] && [ -x "$TARGET_CONTROLLER" ] && [ -x "$TARGET_HARDWARE" ] || {{ echo "controller installation did not provide required executables" >&2; exit 69; }}
}}
case "$MODE" in
  install|update|clean-reinstall|handoff|recover) install_software ;;
  export-state) [ -n "$CURRENT_CTL" ] || {{ echo "$MODE requires the existing controller runtime; software was not changed" >&2; exit 64; }} ;;
esac
check_existing_plan
if [ "$MODE" = update ] || [ "$MODE" = clean-reinstall ] || [ "$MODE" = handoff ]; then
  # Plan output is the last read-only step. Only an accepted plan may switch
  # current, write firmware state, or replace service definitions.
  PLAN_CONFIRM_ARGS=""
  PLAN_RELEASE_ARGS="--release $RELEASE_ID"
  if [ "$OPERATION" = handoff ]; then PLAN_CONFIRM_ARGS="--server $SERVER_URL"; PLAN_RELEASE_ARGS=""; fi
  if [ "$("$TARGET_CTL" --state-root "$STATE_ROOT" lifecycle-plan --current-state "$CURRENT_STATE_FILE" --operation "$OPERATION" $PLAN_CONFIRM_ARGS $PLAN_RELEASE_ARGS | "$PYTHON3" -c 'import json,sys; print(json.load(sys.stdin).get("requires_confirmation", False))')" = true ]; then
    printf 'Accept this lifecycle plan? [y/N] ' > /dev/tty
    IFS= read -r ACCEPT < /dev/tty || ACCEPT=n
    case "$ACCEPT" in y|Y) : ;; *) echo "Plan not accepted; no controller software or binding was changed." >&2; exit 0 ;; esac
  fi
fi
if [ "$MODE" = update ] || [ "$MODE" = clean-reinstall ] || [ "$MODE" = install ]; then
  if [ -L "$NATIVE_ROOT/current" ]; then PREVIOUS_RELEASE="$(readlink -f "$NATIVE_ROOT/current" || true)"; fi
  ln -s "$NATIVE_ROOT/releases/$RELEASE_ID" "$NATIVE_ROOT/.current.new"
  if [ -n "$PREVIOUS_RELEASE" ] && [ "$PREVIOUS_RELEASE" != "$NATIVE_ROOT/releases/$RELEASE_ID" ]; then
    ln -s "$PREVIOUS_RELEASE" "$NATIVE_ROOT/.previous.new"
    mv -Tf "$NATIVE_ROOT/.previous.new" "$NATIVE_ROOT/previous"
  fi
  mv -Tf "$NATIVE_ROOT/.current.new" "$NATIVE_ROOT/current"
  mkdir -p "$FIRMWARE_ROOT"
  install -m 0644 "$STAGE/firmware.bin" "$FIRMWARE_ROOT/samd21-minievolver-$FIRMWARE_VERSION.bin"
  printf '%s\\n' "$FIRMWARE_VERSION" > "$FIRMWARE_ROOT/current"
fi
if [ "$MODE" = update ] || [ "$MODE" = clean-reinstall ] || [ "$MODE" = install ]; then
  EVOLVERCTL="$NATIVE_ROOT/current/bin/evolverctl"; CONTROLLER="$NATIVE_ROOT/current/bin/evolver-controller"; HARDWARE="$NATIVE_ROOT/current/bin/evolver-hardware"
else
  EVOLVERCTL="$CURRENT_CTL"; CONTROLLER="$NATIVE_ROOT/current/bin/evolver-controller"; HARDWARE="$NATIVE_ROOT/current/bin/evolver-hardware"
fi
TOOLCHAIN_ROOT="$NATIVE_ROOT/current/firmware-toolchain"
install -d -m 0750 "$STATE_ROOT"
install -d -m 0755 /usr/local/bin
ln -sfn "$EVOLVERCTL" /usr/local/bin/evolverctl
ln -sfn "$CONTROLLER" /usr/local/bin/evolver-controller
ln -sfn "$HARDWARE" /usr/local/bin/evolver-hardware
SYSTEMD_UNIT_DIR=/etc/systemd/system
SYSTEMD_NIXOS_CONTROL=false
if [ ! -w "$SYSTEMD_UNIT_DIR" ]; then
  # NixOS exposes /etc/systemd/system as an immutable /nix/store symlink.
  # systemd 260 searches this persistent control directory before it.
  SYSTEMD_UNIT_DIR=/etc/systemd/system.control
  install -d -m 0755 "$SYSTEMD_UNIT_DIR" || {{ echo "no writable persistent systemd unit directory" >&2; exit 69; }}
  SYSTEMD_NIXOS_CONTROL=true
fi
if [ "$SYSTEMD_NIXOS_CONTROL" = true ]; then
  cat > "$SYSTEMD_UNIT_DIR/evolver-controller.service" <<EOF
{systemd_unit(executable='${CONTROLLER}', state_directory='evolver-controller', state_root='${STATE_ROOT}', install_config=False, firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
  cat > "$SYSTEMD_UNIT_DIR/evolver-hardware.service" <<EOF
{hardware_systemd_unit(executable='${HARDWARE}', state_directory='evolver-controller', state_root='${STATE_ROOT}', install_config=False, firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
  install -d -m 0755 "$SYSTEMD_UNIT_DIR/multi-user.target.d"
  cat > "$SYSTEMD_UNIT_DIR/multi-user.target.d/evolver-controller.conf" <<EOF
[Unit]
Wants=evolver-controller.service
EOF
  cat > "$SYSTEMD_UNIT_DIR/multi-user.target.d/evolver-hardware.conf" <<EOF
[Unit]
Wants=evolver-hardware.service
EOF
else
  cat > "$SYSTEMD_UNIT_DIR/evolver-controller.service" <<EOF
{systemd_unit(executable='${CONTROLLER}', state_directory='evolver-controller', state_root='${STATE_ROOT}', firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
  cat > "$SYSTEMD_UNIT_DIR/evolver-hardware.service" <<EOF
{hardware_systemd_unit(executable='${HARDWARE}', state_directory='evolver-controller', state_root='${STATE_ROOT}', firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
fi
systemctl daemon-reload
case "$MODE" in
  install|re-enroll)
    [ -n "$TOKEN" ] || {{ echo "--token is required for $MODE" >&2; exit 64; }}
    "$EVOLVERCTL" --state-root "$STATE_ROOT" enroll --server "$SERVER_URL" --token "$TOKEN" --mode repair || {{ [ "$MODE" = install ] && "$EVOLVERCTL" --state-root "$STATE_ROOT" enroll --server "$SERVER_URL" --token "$TOKEN"; }} ;;
  repair|update|clean-reinstall) echo "State and controller identity were preserved at $STATE_ROOT." ;;
  handoff)
    [ -n "$TOKEN" ] || {{ echo "--token is required for $MODE" >&2; exit 64; }}
    "$EVOLVERCTL" --state-root "$STATE_ROOT" enroll --server "$SERVER_URL" --token "$TOKEN" --mode live_handoff ;;
  recover)
    [ -n "$TOKEN" ] || {{ echo "--token is required for $MODE" >&2; exit 64; }}
    [ "$CONFIRM_FORCED_ADOPTION" = true ] || {{ echo "recover requires --confirm-forced-adoption" >&2; exit 64; }}
    "$EVOLVERCTL" --state-root "$STATE_ROOT" enroll --server "$SERVER_URL" --token "$TOKEN" --mode forced_adoption --confirm-forced-adoption ;;
  export-state) "$EVOLVERCTL" --state-root "$STATE_ROOT" export-state "${{EVOLVER_RECOVERY_ARCHIVE:-recovery.tar.zst}}" ;;
  factory-reset) echo "Factory reset is intentionally not performed by this installer. Export recovery state and use a separately confirmed maintenance procedure." >&2; exit 64 ;;
esac
if systemctl is-active --quiet evolver-controller.service; then
  # ``enable --now`` intentionally does not restart an active service.  An
  # explicit restart is required to make a just-installed release effective.
  systemctl restart evolver-hardware.service evolver-controller.service
else
  if [ "$SYSTEMD_NIXOS_CONTROL" = true ]; then
    # The persistent target drop-ins provide boot activation.  A runtime
    # enablement gives the current transaction normal systemctl semantics,
    # without placing either service definition under /run.
    systemctl enable --runtime --now evolver-hardware.service evolver-controller.service
  else
    systemctl enable --now evolver-hardware.service evolver-controller.service
  fi
fi
if ! systemctl is-active --quiet evolver-hardware.service || ! systemctl is-active --quiet evolver-controller.service; then
  if [ "${{INSTALL_BACKEND:-}}" = native ] && [ -L "$NATIVE_ROOT/previous" ]; then
    echo "new native release failed service health; rolling back to previous release" >&2
    ln -s "$(readlink -f "$NATIVE_ROOT/previous")" "$NATIVE_ROOT/.current.rollback"
    mv -Tf "$NATIVE_ROOT/.current.rollback" "$NATIVE_ROOT/current"
    EVOLVERCTL="$NATIVE_ROOT/current/bin/evolverctl"
    CONTROLLER="$NATIVE_ROOT/current/bin/evolver-controller"
    HARDWARE="$NATIVE_ROOT/current/bin/evolver-hardware"
    TOOLCHAIN_ROOT="$NATIVE_ROOT/current/firmware-toolchain"
    if [ -f "$NATIVE_ROOT/current/firmware/version" ]; then
      install -m 0644 "$NATIVE_ROOT/current/firmware/version" "$FIRMWARE_ROOT/current"
    fi
    ln -sfn "$EVOLVERCTL" /usr/local/bin/evolverctl
    ln -sfn "$CONTROLLER" /usr/local/bin/evolver-controller
    ln -sfn "$HARDWARE" /usr/local/bin/evolver-hardware
    if [ "$SYSTEMD_NIXOS_CONTROL" = true ]; then
      cat > "$SYSTEMD_UNIT_DIR/evolver-controller.service" <<EOF
{systemd_unit(executable='${CONTROLLER}', state_directory='evolver-controller', state_root='${STATE_ROOT}', install_config=False, firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
      cat > "$SYSTEMD_UNIT_DIR/evolver-hardware.service" <<EOF
{hardware_systemd_unit(executable='${HARDWARE}', state_directory='evolver-controller', state_root='${STATE_ROOT}', install_config=False, firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
    else
      cat > "$SYSTEMD_UNIT_DIR/evolver-controller.service" <<EOF
{systemd_unit(executable='${CONTROLLER}', state_directory='evolver-controller', state_root='${STATE_ROOT}', firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
      cat > "$SYSTEMD_UNIT_DIR/evolver-hardware.service" <<EOF
{hardware_systemd_unit(executable='${HARDWARE}', state_directory='evolver-controller', state_root='${STATE_ROOT}', firmware_toolchain_root='${TOOLCHAIN_ROOT}')}
EOF
    fi
    systemctl daemon-reload
    systemctl restart evolver-hardware.service evolver-controller.service
  fi
  systemctl is-active --quiet evolver-hardware.service && systemctl is-active --quiet evolver-controller.service || {{ echo "controller update health check failed" >&2; exit 70; }}
fi
"$EVOLVERCTL" --state-root "$STATE_ROOT" install-status
INSTALL_COMMITTED=true
'''


def uninstaller_script(*, default_server_url: str) -> str:
    """Return a server-hosted, offline-capable conservative uninstaller."""
    parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(default_server_url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("uninstaller default server must be an HTTP(S) origin")
    return f'''#!/bin/sh
set -eu
set +x
# Once installed, uninstall is fully offline and uses no GitHub source or
# server credential. The release fallback also handles a broken CLI symlink.
if command -v evolverctl >/dev/null 2>&1; then
  exec evolverctl uninstall "$@"
elif [ -x /opt/evolver-controller/current/bin/evolverctl ]; then
  exec /opt/evolver-controller/current/bin/evolverctl uninstall "$@"
fi
echo "evolverctl is not installed; no software or controller state was changed." >&2
exit 69
'''
