"""Read-only local health report for an eVOLVER controller.

The doctor deliberately never uses the sync endpoint: that endpoint can carry
commands, whereas an operator asking for diagnostics must not accidentally
change a running experiment.  The central reachability probe is the public
``/healthz`` endpoint and the durable connection state reports the outcome of
the last authenticated sync.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen

from .store import EdgeStore

Json = dict[str, Any]
ServiceRunner = Callable[[str], tuple[int, str]]
HealthProbe = Callable[[str], tuple[bool, str]]


def _service_status(unit: str) -> tuple[int, str]:
    """Return a compact systemd state without raising on non-systemd hosts."""
    if not shutil.which("systemctl"):
        return 3, "systemctl is not installed"
    result = subprocess.run(["systemctl", "is-active", unit], check=False,
                            capture_output=True, text=True, timeout=5)
    return result.returncode, (result.stdout.strip() or result.stderr.strip() or "unknown")


def _central_health(server_url: str) -> tuple[bool, str]:
    url = server_url.rstrip("/") + "/healthz"
    try:
        with urlopen(Request(url, method="GET"), timeout=3) as response:  # nosec B310: binding is operator-enrolled
            if response.status == 200:
                return True, url
            return False, f"{url} returned HTTP {response.status}"
    except OSError as error:
        return False, f"{url}: {error.reason if hasattr(error, 'reason') else error}"


def _check(name: str, status: str, detail: str) -> Json:
    return {"name": name, "status": status, "detail": detail}


def doctor_report(
    store: EdgeStore,
    *,
    service_status: ServiceRunner = _service_status,
    central_health: HealthProbe = _central_health,
    application_root: Path | None = None,
) -> Json:
    """Produce a credential-free report suitable for JSON output or support.

    ``PASS`` means the local fact was directly checked; ``WARN`` distinguishes
    an expected offline/development condition from a broken durable state; and
    ``FAIL`` requires operator recovery before relying on the controller.
    """
    checks: list[Json] = []
    identity, binding = store.identity(), store.binding()
    db_exists = store.db_path.is_file()
    checks.append(_check("controller_state_db", "PASS" if db_exists else "FAIL", str(store.db_path)))
    checks.append(_check("controller_identity", "PASS" if identity.get("id") else "FAIL",
                         str(identity.get("id", "missing"))))

    connection = identity.get("connection_state", "unknown")
    if connection == "recovery_required":
        checks.append(_check("recovery_state", "FAIL", "recovery_required; inspect evoctl recovery before resuming"))
    elif connection == "orphaned":
        checks.append(_check("recovery_state", "WARN", "orphaned; local execution remains authoritative until reconciliation"))
    else:
        checks.append(_check("recovery_state", "PASS", connection))

    if not binding:
        checks.append(_check("central_binding", "WARN", "controller is not enrolled"))
        checks.append(_check("central_sync", "WARN", "not checked because no central binding exists"))
    else:
        checks.append(_check("central_binding", "PASS", f"generation {binding['generation']}"))
        reachable, detail = central_health(binding["server_url"])
        status = "PASS" if reachable and connection == "connected" else "WARN"
        if reachable and connection != "connected":
            detail += f"; durable sync state is {connection}"
        checks.append(_check("central_sync", status, detail))

    for unit, name in (("evolver-controller.service", "controller_service"),
                       ("evolver-hardware.service", "hardware_service")):
        code, detail = service_status(unit)
        checks.append(_check(name, "PASS" if code == 0 else "WARN", detail))

    instruments = store.list_instruments()
    physical = [item for item in instruments if item.get("source") == "physical"]
    checks.append(_check("inventory", "PASS" if instruments else "WARN", f"{len(instruments)} instrument(s)"))
    for instrument in physical:
        if instrument.get("identity_state") == "unprovisioned":
            checks.append(_check("physical_identity", "WARN", f"{instrument['id']} is unprovisioned"))
        if instrument.get("connection_state") == "disconnected":
            checks.append(_check("physical_connection", "WARN", f"{instrument['id']} is disconnected"))

    streams = store.telemetry_streams()
    checks.append(_check("telemetry_spool", "PASS", f"{len(streams)} stream(s), {store.telemetry_spool_path}"))

    if application_root:
        app_root = application_root
    elif os.environ.get("META_WEBUI_APPLICATION_ROOT"):
        app_root = Path(os.environ["META_WEBUI_APPLICATION_ROOT"])
    else:
        candidates = (Path.cwd() / "applications" / "deployment", Path("/etc/meta-webui/applications/deployment"))
        app_root = next((candidate for candidate in candidates if (candidate / "app.yaml").is_file()), candidates[0])
    textual_available = importlib.util.find_spec("textual") is not None
    tui_ok = textual_available and (app_root / "app.yaml").is_file()
    detail = str(app_root) if tui_ok else "Textual or application configuration is unavailable"
    checks.append(_check("tui_runtime", "PASS" if tui_ok else "WARN", detail))

    installed = store.meta("controller_software_release")
    desired = store.meta("desired_controller_software_release")
    if desired and desired != installed:
        checks.append(_check("update_state", "WARN", f"update available: {installed or 'unknown'} -> {desired}"))
    else:
        checks.append(_check("update_state", "PASS", f"installed release: {installed or 'unknown'}"))

    counts = {status: sum(check["status"] == status for check in checks) for status in ("PASS", "WARN", "FAIL")}
    return {"controller_id": identity.get("id"), "central_state": connection, "checks": checks, "summary": counts}
