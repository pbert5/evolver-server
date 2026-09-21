"""Focused persistence helpers for the remaining central aggregates.

These helpers deliberately keep the existing JSON-shaped API projections while
making PostgreSQL relations the durable authority.  They accept an open
psycopg connection so callers can include all related writes in one transaction.
"""
from __future__ import annotations

import json
from evolver_server.central_store import CentralStoreConflict
from datetime import date, datetime
from typing import Any, Mapping


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _plain(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain(item) for item in value]
    return value


def _canonical(value: Any) -> str:
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _identity_insert(cur: Any, table: str, key_where: str, key_values: tuple[Any, ...],
                     payload: Mapping[str, Any], insert_sql: str, insert_values: tuple[Any, ...]) -> None:
    cur.execute(f"SELECT * FROM {table} WHERE {key_where}", key_values)
    existing = cur.fetchone()
    if existing is not None:
        existing_payload = {key: _plain(existing.get(key)) for key in payload}
        if _canonical(existing_payload) != _canonical(dict(payload)):
            raise CentralStoreConflict(f"identity conflict in {table}: {key_values}")
        return
    cur.execute(insert_sql, insert_values)


def load_release_history(cur: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    cur.execute("SELECT release_id, release_kind, version, source_revision, manifest_digest, manifest, published_at, published_by, protocol_version, firmware_variant FROM evolver.release_history ORDER BY published_at, release_id")
    releases = [_plain(dict(row)) for row in cur.fetchall()]
    cur.execute("SELECT deployment_id, release_id, controller_id, controller_generation, command_id, requested_by, auth_source, requested_at, based_on_release_id, metadata FROM evolver.release_deployments ORDER BY requested_at, deployment_id")
    deployments = [_plain(dict(row)) for row in cur.fetchall()]
    cur.execute("SELECT event_id, deployment_id, event_type, occurred_at, actor, controller_generation, details FROM evolver.release_deployment_events ORDER BY occurred_at, event_id")
    events = [_plain(dict(row)) for row in cur.fetchall()]
    return releases, deployments, events


def save_release_history(cur: Any, state: Mapping[str, Any]) -> None:
    for release in state.get("release_history", []):
        if not isinstance(release, Mapping):
            continue
        payload = {"release_id": release.get("release_id"), "release_kind": release.get("release_kind"), "version": release.get("version"), "source_revision": release.get("source_revision"), "manifest_digest": release.get("manifest_digest"), "manifest": release.get("manifest", {}), "published_at": release.get("published_at"), "published_by": release.get("published_by"), "protocol_version": release.get("protocol_version"), "firmware_variant": release.get("firmware_variant")}
        _identity_insert(cur, "evolver.release_history", "release_id=%s", (release.get("release_id"),), payload, """INSERT INTO evolver.release_history
            (release_id, release_kind, version, source_revision, manifest_digest, manifest,
             published_at, published_by, protocol_version, firmware_variant)
            VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)""", (
            release.get("release_id"), release.get("release_kind"), release.get("version"),
            release.get("source_revision"), release.get("manifest_digest"), _json(release.get("manifest", {})),
            release.get("published_at"), release.get("published_by"), release.get("protocol_version"),
            release.get("firmware_variant")))
    for deployment in state.get("release_deployments", []):
        if not isinstance(deployment, Mapping):
            continue
        payload = {"deployment_id": deployment.get("deployment_id"), "release_id": deployment.get("release_id"), "controller_id": deployment.get("controller_id"), "controller_generation": deployment.get("controller_generation"), "command_id": deployment.get("command_id"), "requested_by": deployment.get("requested_by"), "auth_source": deployment.get("auth_source"), "requested_at": deployment.get("requested_at"), "based_on_release_id": deployment.get("based_on_release_id"), "metadata": deployment.get("metadata", {})}
        _identity_insert(cur, "evolver.release_deployments", "deployment_id=%s", (deployment.get("deployment_id"),), payload, """INSERT INTO evolver.release_deployments
            (deployment_id, release_id, controller_id, controller_generation, command_id,
             requested_by, auth_source, requested_at, based_on_release_id, metadata)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)""", (
            deployment.get("deployment_id"), deployment.get("release_id"), deployment.get("controller_id"),
            deployment.get("controller_generation"), deployment.get("command_id"), deployment.get("requested_by"),
            deployment.get("auth_source"), deployment.get("requested_at"), deployment.get("based_on_release_id"),
            _json(deployment.get("metadata", {}))))
    for event in state.get("release_events", []):
        if not isinstance(event, Mapping):
            continue
        payload = {"event_id": event.get("event_id"), "deployment_id": event.get("deployment_id"), "event_type": event.get("event_type"), "occurred_at": event.get("occurred_at", event.get("at")), "actor": event.get("actor"), "controller_generation": event.get("controller_generation"), "details": event.get("details", {})}
        _identity_insert(cur, "evolver.release_deployment_events", "event_id=%s", (event.get("event_id"),), payload, """INSERT INTO evolver.release_deployment_events
            (event_id, deployment_id, event_type, occurred_at, actor, controller_generation, details)
            VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)""", (
            event.get("event_id"), event.get("deployment_id"), event.get("event_type"), event.get("occurred_at", event.get("at")),
            event.get("actor"), event.get("controller_generation"), _json(event.get("details", {}))))


def load_calibration(cur: Any) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    cur.execute("SELECT session_id, session FROM evolver.calibration_sessions ORDER BY created_at, session_id")
    sessions = {row["session_id"]: _plain(dict(row["session"])) for row in cur.fetchall()}
    cur.execute("SELECT artifact_id, artifact FROM evolver.calibration_artifacts ORDER BY created_at, artifact_id")
    artifacts = {row["artifact_id"]: _plain(dict(row["artifact"])) for row in cur.fetchall()}
    cur.execute("SELECT event_id, artifact_id, event_type, occurred_at, actor, reason, details, payload FROM evolver.calibration_events ORDER BY occurred_at, event_id")
    events = []
    for row in cur.fetchall():
        event = _plain(dict(row["payload"] or {}))
        if event:
            events.append(event)
            continue
        else:
            event = _plain(dict(row))
        event["id"] = event.pop("event_id", event.get("id"))
        event["type"] = event["event_type"]
        event["at"] = event["occurred_at"]
        if event.get("actor") is not None:
            event["by"] = event["actor"]
        events.append(event)
    return sessions, artifacts, events


def save_calibration(cur: Any, state: Mapping[str, Any]) -> None:
    sessions = state.get("calibration_sessions", {})
    if isinstance(sessions, Mapping):
        for session_id, session in sessions.items():
            if isinstance(session, Mapping):
                payload = {"session_id": session_id, "instrument_id": session.get("instrument_id"), "calibration_type": session.get("calibration_type"), "created_at": session.get("created_at"), "session": session}
                _identity_insert(cur, "evolver.calibration_sessions", "session_id=%s", (session_id,), payload, """INSERT INTO evolver.calibration_sessions (session_id, instrument_id, calibration_type, created_at, session)
                    VALUES (%s,%s,%s,%s,%s::jsonb)
                    """, (
                    session_id, session.get("instrument_id"), session.get("calibration_type"), session.get("created_at"), _json(session)))
    artifacts = state.get("calibration_artifacts", {})
    if isinstance(artifacts, Mapping):
        for artifact_id, artifact in artifacts.items():
            if isinstance(artifact, Mapping):
                payload = {"artifact_id": artifact_id, "artifact_digest": artifact.get("artifact_digest"), "instrument_id": artifact.get("instrument_id"), "vial_position_id": artifact.get("vial_position_id"), "calibration_type": artifact.get("calibration_type"), "created_at": artifact.get("created_at"), "performed_at": artifact.get("performed_at"), "performed_by": artifact.get("performed_by"), "artifact": artifact}
                _identity_insert(cur, "evolver.calibration_artifacts", "artifact_id=%s", (artifact_id,), payload, """INSERT INTO evolver.calibration_artifacts
                    (artifact_id, artifact_digest, instrument_id, vial_position_id, calibration_type, created_at, performed_at, performed_by, artifact)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    """, (
                    artifact_id, artifact.get("artifact_digest"), artifact.get("instrument_id"), artifact.get("vial_position_id"),
                    artifact.get("calibration_type"), artifact.get("created_at"), artifact.get("performed_at"), artifact.get("performed_by"), _json(artifact)))
    for event in state.get("calibration_events", []):
        if not isinstance(event, Mapping):
            continue
        event_id = event.get("id", event.get("event_id"))
        details = event.get("details", {})
        payload = dict(event)
        identity = {"event_id": event_id, "artifact_id": event.get("artifact_id"), "event_type": event.get("event_type", event.get("type", "")), "occurred_at": event.get("occurred_at", event.get("at")), "actor": event.get("actor"), "reason": event.get("reason"), "details": details, "payload": payload}
        _identity_insert(cur, "evolver.calibration_events", "event_id=%s", (event_id,), identity, """INSERT INTO evolver.calibration_events
            (event_id, artifact_id, event_type, occurred_at, actor, reason, details, payload)
            VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)""", (
            event_id, event.get("artifact_id"), event.get("event_type", event.get("type", "")),
            event.get("occurred_at", event.get("at")), event.get("actor"), event.get("reason"), _json(details), _json(payload)))


def load_run_resources(cur: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cur.execute("SELECT assignment_id, run_id, sequence, resource_kind, resource_id, assignment_state, assigned_at, released_at, expires_at, assigned_by, reason, supersedes_id, request_id, controller_generation, based_on_revision, sample_reference, details, payload FROM evolver.run_resource_assignments ORDER BY run_id, sequence")
    assignments = []
    for row in cur.fetchall():
        item = _plain(dict(row["payload"] or {})) or _plain(dict(row))
        item["id"] = item.pop("assignment_id", item.get("id"))
        details = item.pop("details", {}) or {}
        item["details"] = details
        item.update(details)
        assignments.append(item)
    cur.execute("SELECT event_id, run_id, assignment_id, event_type, occurred_at, actor, reason, details, payload FROM evolver.run_resource_events ORDER BY occurred_at, event_id")
    events = []
    for row in cur.fetchall():
        event = _plain(dict(row["payload"] or {})) or _plain(dict(row))
        event["id"] = event.pop("event_id", event.get("id"))
        details = event.pop("details", {}) or {}
        event["details"] = details
        event.update(details)
        events.append(event)
    return assignments, events


def load_od_blank_evidence(cur: Any) -> list[dict[str, Any]]:
    cur.execute("SELECT record_id, controller_id, controller_generation, instrument_id, blank_id, channel_index, raw_adc, captured_at, evidence, payload FROM evolver.od_blank_evidence ORDER BY captured_at, controller_id, record_id")
    records = []
    for row in cur.fetchall():
        record = _plain(dict(row["payload"] or {})) or _plain(dict(row))
        record.update(record.pop("evidence", {}) or {})
        records.append(record)
    return records


def save_od_blank_evidence(cur: Any, state: Mapping[str, Any]) -> None:
    for record in state.get("od_blank_records", []):
        if not isinstance(record, Mapping):
            continue
        reserved = {"record_id", "controller_id", "controller_generation", "instrument_id", "blank_id", "channel_index", "raw_adc", "captured_at"}
        evidence = {key: value for key, value in record.items() if key not in reserved}
        payload = dict(record)
        _identity_insert(cur, "evolver.od_blank_evidence", "controller_id=%s AND controller_generation=%s AND record_id=%s", (record.get("controller_id"), record.get("controller_generation"), record.get("record_id")), {"record_id": record.get("record_id"), "controller_id": record.get("controller_id"), "controller_generation": record.get("controller_generation"), "instrument_id": record.get("instrument_id"), "blank_id": record.get("blank_id"), "channel_index": record.get("channel_index"), "raw_adc": record.get("raw_adc"), "captured_at": record.get("captured_at"), "evidence": evidence, "payload": payload}, """INSERT INTO evolver.od_blank_evidence
            (record_id, controller_id, controller_generation, instrument_id, blank_id, channel_index, raw_adc, captured_at, evidence, payload)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)""", (
            record.get("record_id"), record.get("controller_id"), record.get("controller_generation"), record.get("instrument_id"),
            record.get("blank_id"), record.get("channel_index"), record.get("raw_adc"), record.get("captured_at"), _json(evidence), _json(payload)))


def save_run_resources(cur: Any, state: Mapping[str, Any]) -> None:
    for item in state.get("run_resource_assignments", []):
        if not isinstance(item, Mapping):
            continue
        reserved = {"id", "assignment_id", "run_id", "sequence", "resource_kind", "resource_id", "assignment_state",
                    "assigned_at", "released_at", "expires_at", "assigned_by", "reason", "supersedes_id", "request_id",
                    "controller_generation", "based_on_revision", "sample_reference", "details"}
        details = dict(item.get("details", {})) if isinstance(item.get("details"), Mapping) else {}
        details.update({key: value for key, value in item.items() if key not in reserved})
        payload = dict(item)
        _identity_insert(cur, "evolver.run_resource_assignments", "assignment_id=%s", (item.get("id", item.get("assignment_id")),), {"assignment_id": item.get("id", item.get("assignment_id")), "run_id": item.get("run_id"), "sequence": item.get("sequence"), "resource_kind": item.get("resource_kind"), "resource_id": item.get("resource_id"), "assignment_state": item.get("assignment_state"), "assigned_at": item.get("assigned_at"), "released_at": item.get("released_at"), "expires_at": item.get("expires_at"), "assigned_by": item.get("assigned_by"), "reason": item.get("reason"), "supersedes_id": item.get("supersedes_id"), "request_id": item.get("request_id"), "controller_generation": item.get("controller_generation"), "based_on_revision": item.get("based_on_revision"), "sample_reference": item.get("sample_reference"), "details": details, "payload": payload}, """INSERT INTO evolver.run_resource_assignments
            (assignment_id, run_id, sequence, resource_kind, resource_id, assignment_state, assigned_at, released_at,
             expires_at, assigned_by, reason, supersedes_id, request_id, controller_generation, based_on_revision, sample_reference, details, payload)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,%s::jsonb)""", (
            item.get("id", item.get("assignment_id")), item.get("run_id"), item.get("sequence"), item.get("resource_kind"),
            item.get("resource_id"), item.get("assignment_state"), item.get("assigned_at"), item.get("released_at"),
            item.get("expires_at"), item.get("assigned_by"), item.get("reason"), item.get("supersedes_id"), item.get("request_id"),
            item.get("controller_generation"), item.get("based_on_revision"), _json(item.get("sample_reference")) if item.get("sample_reference") is not None else None, _json(details), _json(payload)))
    for event in state.get("run_resource_events", []):
        if not isinstance(event, Mapping):
            continue
        reserved = {"id", "event_id", "run_id", "assignment_id", "event_type", "occurred_at", "actor", "reason", "details"}
        details = dict(event.get("details", {})) if isinstance(event.get("details"), Mapping) else {}
        details.update({key: value for key, value in event.items() if key not in reserved})
        payload = dict(event)
        _identity_insert(cur, "evolver.run_resource_events", "event_id=%s", (event.get("id", event.get("event_id")),), {"event_id": event.get("id", event.get("event_id")), "run_id": event.get("run_id"), "assignment_id": event.get("assignment_id"), "event_type": event.get("event_type"), "occurred_at": event.get("occurred_at"), "actor": event.get("actor"), "reason": event.get("reason"), "details": details, "payload": payload}, """INSERT INTO evolver.run_resource_events
            (event_id, run_id, assignment_id, event_type, occurred_at, actor, reason, details, payload)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)""", (
            event.get("id", event.get("event_id")), event.get("run_id"), event.get("assignment_id"), event.get("event_type"),
            event.get("occurred_at"), event.get("actor"), event.get("reason"), _json(details), _json(payload)))


class CalibrationRepository:
    """PostgreSQL repository for calibration sessions, artifacts, and events."""

    def load(self) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
        from evolver_server.db import connection
        with connection() as conn, conn.cursor() as cur:
            return load_calibration(cur)

    def save(self, state: Mapping[str, Any]) -> None:
        from evolver_server.db import connection
        with connection() as conn, conn.cursor() as cur:
            save_calibration(cur, state)


class RunResourceRepository:
    """PostgreSQL repository for append-only run-resource assignments/events."""

    def load(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        from evolver_server.db import connection
        with connection() as conn, conn.cursor() as cur:
            return load_run_resources(cur)

    def save(self, state: Mapping[str, Any]) -> None:
        from evolver_server.db import connection
        with connection() as conn, conn.cursor() as cur:
            save_run_resources(cur, state)
