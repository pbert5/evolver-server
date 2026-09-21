"""Central persistence boundaries.

PostgreSQL normalized relations are the production authority. JSON remains
only as an explicit compatibility adapter for migration and tests.
"""
from __future__ import annotations

import json
import os
import hashlib
import copy
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class CentralStoreConflict(RuntimeError):
    """A normalized aggregate changed while an operation was in flight."""


class CentralStoreConfigurationError(RuntimeError):
    """The production persistence boundary is not configured."""


class CentralControllerStore(ABC):
    @abstractmethod
    def load(self) -> tuple[dict[str, Any], int]: ...

    @abstractmethod
    def save(self, state: dict[str, Any], revision: int) -> None: ...


class JsonBootstrapCentralControllerStore(CentralControllerStore):
    """Explicit legacy/test adapter; never selected by normal runtime."""
    def __init__(self, path: Path):
        self.path = path

    def load(self) -> tuple[dict[str, Any], int]:
        if not self.path.exists():
            return {}, 0
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"legacy central state is unreadable: {exc}") from exc
        if not isinstance(value, dict):
            raise RuntimeError("legacy central state must be an object")
        return value, 0

    def save(self, state: dict[str, Any], revision: int) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.path)


class PostgresCentralControllerStore(CentralControllerStore):
    """Normalized PostgreSQL repository used by production runtime.

    The old central JSON document is not read or written. The load/save facade
    remains temporarily for the controller service while aggregate operations
    are migrated, but each write is an upsert to its affected relation and
    never a broad delete/rebuild.
    """
    def __init__(self, url: str, *, bootstrap_path: Path | None = None, _connection: Any | None = None):
        self.url = url
        self.bootstrap_path = None
        self._shared_connection = _connection
        self._loaded_controller_revisions: dict[str, int] = {}

    def _connect(self):
        if self._shared_connection is not None:
            return _ConnectionLease(self._shared_connection)
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(self.url, row_factory=dict_row)

    def load(self) -> tuple[dict[str, Any], int]:
        state: dict[str, Any] = {"enrollment_tokens": {}, "controllers": {}, "commands": {}, "manual_control_leases": {},
                                 "release_history": [], "release_deployments": [], "release_events": [],
                                 "calibration_sessions": {}, "calibration_artifacts": {}, "calibration_events": [],
                                 "run_resource_assignments": [], "run_resource_events": [], "od_blank_records": []}
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, public_key_fingerprint, created_at FROM evolver.webui_controllers ORDER BY created_at, id LIMIT 1")
            row = cur.fetchone()
            if row:
                state["webui_controller"] = _json_row(row)
            cur.execute("SELECT token_digest, token_id, server_url, purpose, expires_at, used_at FROM evolver.enrollment_tokens")
            for row in cur.fetchall():
                state["enrollment_tokens"][row["token_digest"]] = _json_row(row, omit={"token_digest"})
            cur.execute(
                "SELECT p.controller_id, p.public_key_fingerprint, p.connection_state, p.last_sync_at, "
                "p.event_cursors, p.telemetry_cursors, p.projection, p.revision, c.credential_digest, "
                "b.webui_controller_id, b.generation, b.server_url, b.status, b.bound_at "
                "FROM evolver.controller_projections p "
                "LEFT JOIN evolver.controller_credentials c USING (controller_id) "
                "LEFT JOIN evolver.controller_bindings b USING (controller_id)"
            )
            for row in cur.fetchall():
                self._loaded_controller_revisions[row["controller_id"]] = int(row["revision"])
                item = dict(row["projection"] or {}) if isinstance(row["projection"], dict) else {}
                item.update({"public_key_fingerprint": row["public_key_fingerprint"], "connection_state": row["connection_state"], "last_sync_at": _json_value(row["last_sync_at"]), "event_cursors": row["event_cursors"] or {}, "telemetry_cursors": row["telemetry_cursors"] or {}, "credential_digest": row["credential_digest"]})
                if row["generation"] is not None:
                    item["binding"] = {"webui_controller_id": row["webui_controller_id"], "controller_generation": row["generation"], "server_url": row["server_url"], "status": row["status"], "bound_at": _json_value(row["bound_at"])}
                state["controllers"][row["controller_id"]] = item
            cur.execute("SELECT command_id, controller_id, command FROM evolver.commands ORDER BY requested_at, command_id")
            for row in cur.fetchall():
                state["commands"].setdefault(row["controller_id"], []).append(row["command"] or {})
            cur.execute("SELECT command_id, controller_id, acknowledgement FROM evolver.command_acknowledgements ORDER BY acknowledged_at, command_id")
            for row in cur.fetchall():
                state["controllers"].setdefault(row["controller_id"], {}).setdefault("acknowledgements", []).append(row["acknowledgement"] or {})
            cur.execute("SELECT controller_id, manifest, summary FROM evolver.recovery_metadata")
            for row in cur.fetchall():
                controller = state["controllers"].setdefault(row["controller_id"], {})
                controller["recovery_manifest"] = row["manifest"]
                controller["recovery_summary"] = row["summary"]
            cur.execute("SELECT controller_id, path, occurred_at, detail FROM evolver.handoff_history ORDER BY id")
            for row in cur.fetchall():
                state["controllers"].setdefault(row["controller_id"], {}).setdefault("binding_history", []).append(_json_row(row, omit={"controller_id"}))
            cur.execute("SELECT lease_id, controller_id, controller_generation, holder, lease_token, acquired_at, expires_at, revoked_at, revoked_by, status FROM evolver.manual_control_leases")
            for row in cur.fetchall():
                state["manual_control_leases"][row["controller_id"]] = _json_row(row, omit={"controller_id"})
            cur.execute("SELECT controller_id, endpoint_id, endpoint_url, assigned_at, assigned_by FROM evolver.controller_endpoint_assignments")
            for row in cur.fetchall():
                assignment = _json_row(row, omit={"controller_id", "endpoint_url"})
                assignment["url"] = _json_value(row["endpoint_url"])
                state.setdefault("endpoint_assignments", {})[row["controller_id"]] = assignment
            from .persistence.aggregates import load_calibration, load_od_blank_evidence, load_release_history, load_run_resources
            state["release_history"], state["release_deployments"], state["release_events"] = load_release_history(cur)
            state["calibration_sessions"], state["calibration_artifacts"], state["calibration_events"] = load_calibration(cur)
            state["run_resource_assignments"], state["run_resource_events"] = load_run_resources(cur)
            state["od_blank_records"] = load_od_blank_evidence(cur)
        return state, 0

    def save(self, state: dict[str, Any], revision: int) -> None:
        baseline = getattr(state, "_baseline", None)
        controller_revisions = getattr(state, "_controller_revisions", {})
        if isinstance(baseline, dict):
            # A compatibility caller may still present a reconstructed state,
            # but only top-level aggregates that changed since load are
            # eligible for persistence. This prevents an unrelated stale
            # snapshot from replaying every aggregate in the database.
            state = dict(state)
            for key in ("enrollment_tokens", "commands", "manual_control_leases", "endpoint_assignments"):
                if state.get(key) == baseline.get(key):
                    state[key] = {} if isinstance(state.get(key), dict) else []
            for key in ("release_history", "release_deployments", "release_events", "calibration_events", "run_resource_assignments", "run_resource_events", "od_blank_records"):
                if state.get(key) == baseline.get(key):
                    state[key] = []
            def changed_records(key: str, identity_keys: tuple[str, ...]) -> list[Any]:
                prior = baseline.get(key, [])
                old = {tuple(item.get(field) for field in identity_keys): item for item in prior if isinstance(item, dict)}
                return [item for item in state.get(key, []) if not isinstance(item, dict) or item != old.get(tuple(item.get(field) for field in identity_keys))]
            for key, identity_keys in (
                ("release_history", ("release_id",)), ("release_deployments", ("deployment_id",)),
                ("release_events", ("event_id",)), ("calibration_events", ("id", "event_id")),
                ("run_resource_assignments", ("id", "assignment_id")), ("run_resource_events", ("id", "event_id")),
                ("od_blank_records", ("controller_id", "controller_generation", "record_id")),
            ):
                if isinstance(state.get(key), list):
                    state[key] = changed_records(key, identity_keys)
            for key in ("enrollment_tokens", "calibration_sessions", "calibration_artifacts", "manual_control_leases", "endpoint_assignments"):
                if isinstance(state.get(key), dict) and isinstance(baseline.get(key), dict):
                    state[key] = {item_key: item for item_key, item in state[key].items() if item != baseline[key].get(item_key)}
            if isinstance(state.get("commands"), dict) and isinstance(baseline.get("commands"), dict):
                state["commands"] = {
                    controller_id: [item for item in commands if item != next((old for old in baseline["commands"].get(controller_id, []) if isinstance(old, dict) and old.get("command_id") == item.get("command_id")), None)]
                    for controller_id, commands in state["commands"].items()
                }
        with self._connect() as conn, conn.cursor() as cur:
            identity = state.get("webui_controller")
            if isinstance(identity, dict) and identity.get("id"):
                cur.execute("INSERT INTO evolver.webui_controllers(id, public_key_fingerprint, created_at) VALUES (%s,%s,COALESCE(%s::timestamptz,now())) ON CONFLICT (id) DO UPDATE SET public_key_fingerprint=EXCLUDED.public_key_fingerprint", (identity["id"], identity.get("public_key_fingerprint"), identity.get("created_at")))
            for digest, token in state.get("enrollment_tokens", {}).items():
                if isinstance(token, dict):
                    cur.execute("INSERT INTO evolver.enrollment_tokens(token_digest, token_id, server_url, purpose, expires_at, used_at) VALUES (%s,%s,%s,%s,%s::timestamptz,%s::timestamptz) ON CONFLICT (token_digest) DO UPDATE SET used_at=EXCLUDED.used_at", (digest, token.get("id"), token.get("server_url"), token.get("purpose"), token.get("expires_at"), token.get("used_at")))
            for controller_id, item in state.get("controllers", {}).items():
                if not isinstance(item, dict):
                    continue
                if isinstance(baseline, dict) and item == baseline.get("controllers", {}).get(controller_id):
                    continue
                expected = controller_revisions.get(controller_id)
                if expected is None:
                    cur.execute("""INSERT INTO evolver.controller_projections
                        (controller_id, public_key_fingerprint, connection_state, last_sync_at,
                         event_cursors, telemetry_cursors, projection, revision)
                        VALUES (%s,%s,%s,%s::timestamptz,%s::jsonb,%s::jsonb,%s::jsonb,0)
                        ON CONFLICT (controller_id) DO NOTHING""", (controller_id, item.get("public_key_fingerprint"), item.get("connection_state"), item.get("last_sync_at"), json.dumps(item.get("event_cursors", {})), json.dumps(item.get("telemetry_cursors", {})), json.dumps(item)))
                    if cur.rowcount == 0:
                        raise CentralStoreConflict(f"controller aggregate {controller_id} was created concurrently")
                else:
                    cur.execute("""UPDATE evolver.controller_projections SET
                        public_key_fingerprint=%s, connection_state=%s, last_sync_at=%s::timestamptz,
                        event_cursors=%s::jsonb, telemetry_cursors=%s::jsonb, projection=%s::jsonb,
                        revision=revision+1 WHERE controller_id=%s AND revision=%s""", (item.get("public_key_fingerprint"), item.get("connection_state"), item.get("last_sync_at"), json.dumps(item.get("event_cursors", {})), json.dumps(item.get("telemetry_cursors", {})), json.dumps(item), controller_id, expected))
                    if cur.rowcount != 1:
                        raise CentralStoreConflict(f"stale controller aggregate {controller_id}")
                if isinstance(item.get("credential_digest"), str):
                    cur.execute("INSERT INTO evolver.controller_credentials(controller_id, credential_digest) VALUES (%s,%s) ON CONFLICT (controller_id) DO UPDATE SET credential_digest=EXCLUDED.credential_digest", (controller_id, item["credential_digest"]))
                binding = item.get("binding")
                if isinstance(binding, dict) and isinstance(binding.get("controller_generation"), int) and binding["controller_generation"] > 0:
                    cur.execute("INSERT INTO evolver.controller_bindings(controller_id, webui_controller_id, generation, server_url, status, bound_at) VALUES (%s,%s,%s,%s,%s,%s::timestamptz) ON CONFLICT (controller_id) DO UPDATE SET generation=EXCLUDED.generation, server_url=EXCLUDED.server_url, status=EXCLUDED.status, bound_at=EXCLUDED.bound_at", (controller_id, binding.get("webui_controller_id"), binding["controller_generation"], binding.get("server_url"), binding.get("status"), binding.get("bound_at")))
                if item.get("recovery_manifest") is not None or item.get("recovery_summary") is not None:
                    cur.execute("INSERT INTO evolver.recovery_metadata(controller_id, manifest, summary) VALUES (%s,%s::jsonb,%s::jsonb) ON CONFLICT (controller_id) DO UPDATE SET manifest=EXCLUDED.manifest, summary=EXCLUDED.summary, updated_at=now()", (controller_id, json.dumps(item.get("recovery_manifest")), json.dumps(item.get("recovery_summary"))))
                for history in item.get("binding_history", []) if isinstance(item.get("binding_history"), list) else []:
                    if isinstance(history, dict) and history.get("path") and history.get("at"):
                        cur.execute("INSERT INTO evolver.handoff_history(controller_id, path, occurred_at, detail) SELECT %s,%s,%s::timestamptz,%s::jsonb WHERE NOT EXISTS (SELECT 1 FROM evolver.handoff_history WHERE controller_id=%s AND path=%s AND occurred_at=%s::timestamptz)", (controller_id, history["path"], history["at"], json.dumps(history), controller_id, history["path"], history["at"]))
                for acknowledgement in item.get("acknowledgements", []) if isinstance(item.get("acknowledgements"), list) else []:
                    if isinstance(acknowledgement, dict) and acknowledgement.get("command_id"):
                        cur.execute("INSERT INTO evolver.command_acknowledgements(command_id, controller_id, acknowledgement) VALUES (%s,%s,%s::jsonb) ON CONFLICT (command_id, controller_id) DO UPDATE SET acknowledgement=EXCLUDED.acknowledgement", (acknowledgement["command_id"], controller_id, json.dumps(acknowledgement)))
            for controller_id, commands in state.get("commands", {}).items():
                for command in commands if isinstance(commands, list) else []:
                    if isinstance(command, dict) and command.get("command_id"):
                        cur.execute("INSERT INTO evolver.commands(command_id, controller_id, generation, disposition, requested_by, auth_source, requested_at, command) VALUES (%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::jsonb) ON CONFLICT (command_id) DO UPDATE SET disposition=EXCLUDED.disposition, command=EXCLUDED.command", (command["command_id"], controller_id, command.get("controller_generation", 0), command.get("disposition"), command.get("requested_by"), command.get("auth_source"), command.get("requested_at"), json.dumps(command)))
            for controller_id, lease in state.get("manual_control_leases", {}).items():
                if isinstance(lease, dict) and lease.get("lease_id"):
                    cur.execute("INSERT INTO evolver.manual_control_leases(lease_id, controller_id, controller_generation, holder, lease_token, acquired_at, expires_at, revoked_at, revoked_by, status) VALUES (%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz,%s::timestamptz,%s,%s) ON CONFLICT (lease_id) DO UPDATE SET expires_at=EXCLUDED.expires_at, revoked_at=EXCLUDED.revoked_at, revoked_by=EXCLUDED.revoked_by, status=EXCLUDED.status", (lease["lease_id"], controller_id, lease.get("controller_generation"), lease.get("holder"), lease.get("lease_token"), lease.get("acquired_at"), lease.get("expires_at"), lease.get("revoked_at"), lease.get("revoked_by"), lease.get("status", "active")))
            for controller_id, assignment in state.get("endpoint_assignments", {}).items():
                if isinstance(assignment, dict) and assignment.get("endpoint_id"):
                    cur.execute("INSERT INTO evolver.controller_endpoint_assignments(controller_id, endpoint_id, endpoint_url, assigned_at, assigned_by) VALUES (%s,%s,%s,%s::timestamptz,%s) ON CONFLICT (controller_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id, endpoint_url=EXCLUDED.endpoint_url, assigned_at=EXCLUDED.assigned_at, assigned_by=EXCLUDED.assigned_by", (controller_id, assignment["endpoint_id"], assignment.get("url"), assignment.get("assigned_at"), assignment.get("assigned_by")))
            from .persistence.aggregates import save_calibration, save_od_blank_evidence, save_release_history, save_run_resources
            save_release_history(cur, state)
            save_calibration(cur, state)
            save_run_resources(cur, state)
            save_od_blank_evidence(cur, state)


def _json_value(value: Any) -> Any:
    return value.isoformat().replace("+00:00", "Z") if hasattr(value, "isoformat") else value


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class _ConnectionLease:
    """No-op context wrapper for a caller-owned transaction connection."""

    def __init__(self, connection: Any):
        self.connection = connection

    def __enter__(self) -> Any:
        return self.connection

    def __exit__(self, *_: Any) -> bool:
        return False


def _json_row(row: dict[str, Any], *, omit: set[str] | None = None) -> dict[str, Any]:
    omit = omit or set()
    return {key: _json_value(value) for key, value in row.items() if key not in omit}


def configured_store(*, json_path: Path, explicit_state_root: bool) -> CentralControllerStore:
    """Select PostgreSQL at runtime; JSON is explicit migration/test only."""
    if explicit_state_root:
        return JsonBootstrapCentralControllerStore(json_path)
    url = os.environ.get("META_WEBUI_INTERFACE_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if not url:
        raise CentralStoreConfigurationError("DATABASE_URL is required; JSON runtime fallback is disabled")
    return PostgresCentralControllerStore(url)
