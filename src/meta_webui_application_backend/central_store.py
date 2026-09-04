"""Persistent repository for the central eVOLVER coordination projection.

The protocol layer deliberately deals in one document while this repository
owns PostgreSQL access.  The document is retained for backwards-compatible
recovery/import handling; the relational projections make the operational
objects queryable without putting credentials or raw telemetry in browser
configuration.  JSON is only a bootstrap source, never the production store.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from meta_webui_application_backend.evolver_history import payload_digest


class CentralStoreConflict(RuntimeError):
    """Another WebUI worker changed central state during this operation."""


class CentralControllerStore(ABC):
    @abstractmethod
    def load(self) -> tuple[dict[str, Any], int]: ...

    @abstractmethod
    def save(self, state: dict[str, Any], revision: int) -> None: ...


class JsonBootstrapCentralControllerStore(CentralControllerStore):
    """Compatibility-only store used for explicit state roots and migration."""
    def __init__(self, path: Path): self.path = path

    def load(self) -> tuple[dict[str, Any], int]:
        if not self.path.exists(): return {}, 0
        try: value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc: raise RuntimeError(f"central eVOLVER state is unreadable: {exc}") from exc
        if not isinstance(value, dict): raise RuntimeError("central eVOLVER state must be an object")
        return value, 0

    def save(self, state: dict[str, Any], revision: int) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
        temporary.replace(self.path)


class PostgresCentralControllerStore(CentralControllerStore):
    """PostgreSQL source of truth with optimistic revision fencing.

    Migration ``0011_evolver_central_controller`` creates these relations.
    A transaction locks the singleton document row and mirrors its queryable
    projections atomically, so token consumption/binding changes cannot be
    partially committed.
    """
    def __init__(self, url: str, *, bootstrap_path: Path | None = None):
        self.url, self.bootstrap_path = url, bootstrap_path

    def _connect(self):
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(self.url, row_factory=dict_row)

    def load(self) -> tuple[dict[str, Any], int]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT payload, revision FROM evolver.central_state WHERE singleton = true")
            row = cur.fetchone()
            if row: return dict(row["payload"] or {}), int(row["revision"])
            bootstrap = JsonBootstrapCentralControllerStore(self.bootstrap_path).load()[0] if self.bootstrap_path and self.bootstrap_path.exists() else {}
            cur.execute("INSERT INTO evolver.central_state(singleton, payload, revision, migrated_from_json_at) VALUES (true, %s::jsonb, 0, CASE WHEN %s THEN now() ELSE NULL END) ON CONFLICT (singleton) DO NOTHING", (json.dumps(bootstrap), bool(bootstrap)))
            return bootstrap, 0

    def save(self, state: dict[str, Any], revision: int) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE evolver.central_state SET payload=%s::jsonb, revision=revision+1, updated_at=now() WHERE singleton=true AND revision=%s", (json.dumps(state), revision))
            if cur.rowcount != 1: raise CentralStoreConflict("central controller state changed concurrently; retry request")
            self._mirror(cur, state)

    @staticmethod
    def _mirror(cur: Any, state: dict[str, Any]) -> None:
        identity = state.get("webui_controller", {})
        if isinstance(identity, dict) and identity.get("id"):
            cur.execute("INSERT INTO evolver.webui_controllers(id, public_key_fingerprint, created_at) VALUES (%s,%s,COALESCE(%s::timestamptz,now())) ON CONFLICT (id) DO NOTHING", (identity["id"], identity.get("public_key_fingerprint"), identity.get("created_at")))
        cur.execute("DELETE FROM evolver.enrollment_tokens; DELETE FROM evolver.controller_bindings; DELETE FROM evolver.controller_credentials; DELETE FROM evolver.controller_projections; DELETE FROM evolver.command_acknowledgements; DELETE FROM evolver.commands; DELETE FROM evolver.handoff_history; DELETE FROM evolver.recovery_metadata; DELETE FROM evolver.manual_control_leases")
        for digest, token in state.get("enrollment_tokens", {}).items():
            if isinstance(token, dict): cur.execute("INSERT INTO evolver.enrollment_tokens(token_digest, token_id, server_url, purpose, expires_at, used_at) VALUES (%s,%s,%s,%s,%s::timestamptz,%s::timestamptz)", (digest, token.get("id"), token.get("server_url"), token.get("purpose"), token.get("expires_at"), token.get("used_at")))
        for controller_id, item in state.get("controllers", {}).items():
            if not isinstance(item, dict): continue
            binding = item.get("binding", {})
            generation = binding.get("controller_generation")
            cur.execute("INSERT INTO evolver.controller_projections(controller_id, public_key_fingerprint, connection_state, last_sync_at, event_cursors, telemetry_cursors, projection) VALUES (%s,%s,%s,%s::timestamptz,%s::jsonb,%s::jsonb,%s::jsonb)", (controller_id, item.get("public_key_fingerprint"), item.get("connection_state"), item.get("last_sync_at"), json.dumps(item.get("event_cursors", {})), json.dumps(item.get("telemetry_cursors", {})), json.dumps(item)))
            cur.execute("INSERT INTO evolver.controller_credentials(controller_id, credential_digest) VALUES (%s,%s)", (controller_id, item.get("credential_digest")))
            cur.execute("INSERT INTO evolver.controller_bindings(controller_id, webui_controller_id, generation, server_url, status, bound_at) VALUES (%s,%s,%s,%s,%s,%s::timestamptz)", (controller_id, binding.get("webui_controller_id"), binding.get("controller_generation"), binding.get("server_url"), binding.get("status"), binding.get("bound_at")))
            for history in item.get("binding_history", []):
                if isinstance(history, dict): cur.execute("INSERT INTO evolver.handoff_history(controller_id, path, occurred_at, detail) VALUES (%s,%s,%s::timestamptz,%s::jsonb)", (controller_id, history.get("path"), history.get("at"), json.dumps(history)))
            for acknowledgement in item.get("acknowledgements", []):
                if isinstance(acknowledgement, dict) and acknowledgement.get("command_id"):
                    cur.execute("INSERT INTO evolver.command_acknowledgements(command_id, controller_id, acknowledgement) VALUES (%s,%s,%s::jsonb)", (acknowledgement["command_id"], controller_id, json.dumps(acknowledgement)))
            if item.get("recovery_manifest") is not None: cur.execute("INSERT INTO evolver.recovery_metadata(controller_id, manifest, summary) VALUES (%s,%s::jsonb,%s::jsonb)", (controller_id, json.dumps(item.get("recovery_manifest")), json.dumps(item.get("recovery_summary"))))
            # Append normalized edge facts separately from the replaceable
            # controller projection.  Invalid legacy records remain in the
            # compatibility document but cannot become durable history.
            if isinstance(generation, int) and generation > 0:
                for event in item.get("events", []):
                    if not isinstance(event, dict) or not isinstance(event.get("run_id"), str) or not isinstance(event.get("sequence"), int) or event["sequence"] <= 0:
                        continue
                    payload = event.get("payload") if isinstance(event.get("payload"), dict) else event
                    digest = payload_digest(payload)
                    cur.execute("INSERT INTO evolver.controller_event_history(controller_id, controller_generation, run_id, sequence, event_id, event_type, occurred_at, payload, payload_digest) VALUES (%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::jsonb,%s) ON CONFLICT (controller_id, controller_generation, run_id, sequence) DO NOTHING", (controller_id, generation, event["run_id"], event["sequence"], event.get("event_id"), event.get("event_type", event.get("type", "unknown")), event.get("occurred_at", event.get("at")), json.dumps(payload), digest))
                    cur.execute("SELECT payload_digest FROM evolver.controller_event_history WHERE controller_id=%s AND controller_generation=%s AND run_id=%s AND sequence=%s", (controller_id, generation, event["run_id"], event["sequence"]))
                    if cur.fetchone()["payload_digest"] != digest:
                        raise CentralStoreConflict("event sequence conflicts with durable central record")
                for record in item.get("telemetry", []):
                    if not isinstance(record, dict) or not isinstance(record.get("stream_id"), str) or not isinstance(record.get("sequence"), int) or record["sequence"] <= 0:
                        continue
                    payload = record.get("payload") if isinstance(record.get("payload"), dict) else record
                    digest = payload_digest(payload)
                    cur.execute("INSERT INTO evolver.controller_telemetry_history(controller_id, controller_generation, stream_id, sequence, instrument_id, vial_position_id, captured_at, metric, value, unit, payload, payload_digest) VALUES (%s,%s,%s,%s,%s,%s,%s::timestamptz,%s,%s,%s,%s::jsonb,%s) ON CONFLICT (controller_id, controller_generation, stream_id, sequence) DO NOTHING", (controller_id, generation, record["stream_id"], record["sequence"], record.get("instrument_id"), record.get("vial_position_id"), record.get("captured_at", record.get("timestamp", record.get("at"))), record.get("metric"), record.get("value"), record.get("unit"), json.dumps(payload), digest))
                    cur.execute("SELECT payload_digest FROM evolver.controller_telemetry_history WHERE controller_id=%s AND controller_generation=%s AND stream_id=%s AND sequence=%s", (controller_id, generation, record["stream_id"], record["sequence"]))
                    if cur.fetchone()["payload_digest"] != digest:
                        raise CentralStoreConflict("telemetry sequence conflicts with durable central record")
        for controller_id, commands in state.get("commands", {}).items():
            for command in commands if isinstance(commands, list) else []:
                if not isinstance(command, dict): continue
                cur.execute("INSERT INTO evolver.commands(command_id, controller_id, generation, disposition, requested_by, auth_source, requested_at, delivery_eligible, expires_at, expired_at, acknowledged_at, command) VALUES (%s,%s,%s,%s,%s,%s,%s::timestamptz,%s,%s::timestamptz,%s::timestamptz,%s::timestamptz,%s::jsonb)", (command.get("command_id"), controller_id, command.get("controller_generation"), command.get("disposition"), command.get("requested_by"), command.get("auth_source"), command.get("requested_at"), command.get("delivery_eligible", command.get("disposition") not in {"completed", "stored", "failed", "expired", "rejected_stale_generation", "rejected_stale_revision", "rejected_unsafe", "rejected_invalid", "safe_stop_intent_recorded"}), command.get("expires_at"), command.get("expired_at"), command.get("acknowledged_at"), json.dumps(command)))
        for controller_id, lease in state.get("manual_control_leases", {}).items():
            if isinstance(lease, dict) and lease.get("lease_id"):
                cur.execute("INSERT INTO evolver.manual_control_leases(lease_id, controller_id, controller_generation, holder, lease_token, acquired_at, expires_at, revoked_at, revoked_by, status) VALUES (%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz,%s::timestamptz,%s,%s)", (lease["lease_id"], controller_id, lease.get("controller_generation"), lease.get("holder"), lease.get("lease_token"), lease.get("acquired_at"), lease.get("expires_at"), lease.get("revoked_at"), lease.get("revoked_by"), lease.get("status", "active")))
        for controller_id, assignment in state.get("endpoint_assignments", {}).items():
            if isinstance(assignment, dict) and assignment.get("endpoint_id"):
                cur.execute("INSERT INTO evolver.controller_endpoint_assignments(controller_id, endpoint_id, endpoint_url, assigned_at, assigned_by) VALUES (%s,%s,%s,%s::timestamptz,%s) ON CONFLICT (controller_id) DO UPDATE SET endpoint_id=EXCLUDED.endpoint_id, endpoint_url=EXCLUDED.endpoint_url, assigned_at=EXCLUDED.assigned_at, assigned_by=EXCLUDED.assigned_by", (controller_id, assignment["endpoint_id"], assignment.get("url"), assignment.get("assigned_at"), assignment.get("assigned_by")))
        for event in state.get("audit_events", []):
            if isinstance(event, dict) and event.get("id"):
                cur.execute("INSERT INTO evolver.control_audit_events(event_id, event_type, occurred_at, actor, details) VALUES (%s,%s,%s::timestamptz,%s,%s::jsonb) ON CONFLICT (event_id) DO NOTHING", (event["id"], event.get("event_type"), event.get("occurred_at"), event.get("actor"), json.dumps(event.get("details", {}))))
        for event in state.get("controller_lifecycle_events", []):
            if isinstance(event, dict) and event.get("id"):
                cur.execute("INSERT INTO evolver.controller_lifecycle_events(event_id, controller_id, event_type, occurred_at, actor, details) VALUES (%s,%s,%s,%s::timestamptz,%s,%s::jsonb) ON CONFLICT (event_id) DO NOTHING", (event["id"], event.get("controller_id"), event.get("event_type"), event.get("occurred_at"), event.get("actor"), json.dumps(event)))
        for request in state.get("rollback_requests", []):
            if isinstance(request, dict) and request.get("request_id"):
                cur.execute("INSERT INTO evolver.rollback_requests(request_id, controller_id, controller_generation, release_id, requested_at, requested_by, auth_source, reason, status, idempotency_key) VALUES (%s,%s,%s,%s,%s::timestamptz,%s,%s,%s,%s,%s) ON CONFLICT (request_id) DO NOTHING", (request["request_id"], request.get("controller_id"), request.get("controller_generation"), request.get("release_id"), request.get("requested_at"), request.get("requested_by"), request.get("auth_source"), request.get("reason"), request.get("status", "requested"), request.get("idempotency_key")))
        for release in state.get("release_history", []):
            if not isinstance(release, dict) or not release.get("release_id"):
                continue
            cur.execute(
                "INSERT INTO evolver.release_history(release_id, release_kind, version, source_revision, manifest_digest, manifest, published_at, published_by, protocol_version, firmware_variant) VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s::timestamptz,%s,%s,%s) ON CONFLICT (release_id) DO NOTHING",
                (release["release_id"], release.get("release_kind"), release.get("version"), release.get("source_revision"), release.get("manifest_digest"), json.dumps(release.get("manifest", {})), release.get("published_at"), release.get("published_by"), release.get("protocol_version"), release.get("firmware_variant")),
            )
        for deployment in state.get("release_deployments", []):
            if not isinstance(deployment, dict) or not deployment.get("deployment_id"):
                continue
            cur.execute(
                "INSERT INTO evolver.release_deployments(deployment_id, release_id, controller_id, controller_generation, command_id, requested_by, auth_source, requested_at, based_on_release_id, metadata) VALUES (%s,%s,%s,%s,%s,%s,%s,%s::timestamptz,%s,%s::jsonb) ON CONFLICT (deployment_id) DO NOTHING",
                (deployment["deployment_id"], deployment.get("release_id"), deployment.get("controller_id"), deployment.get("controller_generation"), deployment.get("command_id"), deployment.get("requested_by"), deployment.get("auth_source"), deployment.get("requested_at"), deployment.get("based_on_release_id"), json.dumps(deployment.get("metadata", {}))),
            )
        for event in state.get("release_events", []):
            if not isinstance(event, dict) or not event.get("deployment_id"):
                continue
            cur.execute(
                "INSERT INTO evolver.release_deployment_events(event_id, deployment_id, event_type, occurred_at, actor, controller_generation, details) VALUES (%s,%s,%s,%s::timestamptz,%s,%s,%s::jsonb) ON CONFLICT (event_id) DO NOTHING",
                (event.get("event_id", event.get("id")), event["deployment_id"], event.get("event_type"), event.get("occurred_at"), event.get("actor"), event.get("controller_generation"), json.dumps(event.get("details", {}))),
            )
        # Calibration relations are append-only: unlike the legacy read
        # projections above, never delete/rewrite accepted artifacts or facts.
        for artifact_id, artifact in state.get("calibration_artifacts", {}).items():
            if not isinstance(artifact, dict) or not isinstance(artifact.get("artifact_digest"), str):
                continue
            cur.execute(
                "INSERT INTO evolver.calibration_artifacts(artifact_id, artifact_digest, instrument_id, vial_position_id, calibration_type, created_at, performed_at, performed_by, artifact) "
                "VALUES (%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz,%s,%s::jsonb) ON CONFLICT (artifact_id) DO NOTHING",
                (artifact_id, artifact["artifact_digest"], artifact.get("instrument_id"), artifact.get("vial_position_id"),
                 artifact.get("calibration_type"), artifact.get("created_at"), artifact.get("performed_at"), artifact.get("performed_by"), json.dumps(artifact)),
            )
        for event in state.get("calibration_events", []):
            if not isinstance(event, dict) or not isinstance(event.get("id"), str) or not isinstance(event.get("artifact_id"), str):
                continue
            event_type = event.get("event_type", event.get("type"))
            occurred_at = event.get("occurred_at", event.get("at"))
            if not isinstance(event_type, str) or not occurred_at:
                continue
            details = event.get("details") if isinstance(event.get("details"), dict) else event
            cur.execute(
                "INSERT INTO evolver.calibration_events(event_id, artifact_id, event_type, occurred_at, actor, reason, details) "
                "VALUES (%s,%s,%s,%s::timestamptz,%s,%s,%s::jsonb) ON CONFLICT (event_id) DO NOTHING",
                (event["id"], event["artifact_id"], event_type, occurred_at, event.get("actor", event.get("by")), event.get("reason"), json.dumps(details)),
            )
            if event_type in {"distribution_requested", "distribution_stored", "distribution_failed"} and all(isinstance(details.get(key), str) for key in ("command_id", "controller_id", "artifact_digest")) and isinstance(details.get("controller_generation"), int):
                cur.execute(
                    "INSERT INTO evolver.calibration_distribution_facts(event_id, artifact_id, command_id, controller_id, controller_generation, artifact_digest, state, request_id) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING",
                    (event["id"], event["artifact_id"], details["command_id"], details["controller_id"], details["controller_generation"], details["artifact_digest"],
                     {"distribution_requested": "requested", "distribution_stored": "stored", "distribution_failed": "failed"}[event_type], details.get("request_id")),
                )
        # Run resource history is append-only.  Unlike the legacy controller
        # projections, rows are never cleared or rewritten during a state
        # mirror; retries are absorbed by the stable fact identifiers.
        for assignment in state.get("run_resource_assignments", []):
            if not isinstance(assignment, dict) or not assignment.get("id"):
                continue
            cur.execute(
                "INSERT INTO evolver.run_resource_assignments(assignment_id, run_id, sequence, resource_kind, resource_id, assignment_state, assigned_at, released_at, expires_at, assigned_by, reason, supersedes_id, request_id, sample_reference, details) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s::timestamptz,%s::timestamptz,%s::timestamptz,%s,%s,%s,%s,%s::jsonb,%s::jsonb) ON CONFLICT (assignment_id) DO NOTHING",
                (assignment["id"], assignment.get("run_id"), assignment.get("sequence"), assignment.get("resource_kind"), assignment.get("resource_id"), assignment.get("assignment_state"),
                 assignment.get("assigned_at"), assignment.get("released_at"), assignment.get("expires_at"), assignment.get("assigned_by"), assignment.get("reason"), assignment.get("supersedes_id"), assignment.get("request_id"),
                 json.dumps(assignment.get("sample_reference")) if assignment.get("sample_reference") is not None else None, json.dumps(assignment)),
            )
        for event in state.get("run_resource_events", []):
            if not isinstance(event, dict) or not event.get("id"):
                continue
            cur.execute(
                "INSERT INTO evolver.run_resource_events(event_id, run_id, assignment_id, event_type, occurred_at, actor, reason, details) VALUES (%s,%s,%s,%s,%s::timestamptz,%s,%s,%s::jsonb) ON CONFLICT (event_id) DO NOTHING",
                (event["id"], event.get("run_id"), event.get("assignment_id"), event.get("event_type"), event.get("occurred_at"), event.get("actor"), event.get("reason"), json.dumps(event)),
            )


def configured_store(*, json_path: Path, explicit_state_root: bool) -> CentralControllerStore:
    """Use PostgreSQL when configured; explicit state roots remain test/import seams."""
    url = os.environ.get("META_WEBUI_INTERFACE_DATABASE_URL") or os.environ.get("DATABASE_URL")
    if url and not explicit_state_root: return PostgresCentralControllerStore(url, bootstrap_path=json_path)
    return JsonBootstrapCentralControllerStore(json_path)
