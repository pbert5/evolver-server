"""Focused persistence helpers for the remaining central aggregates.

These helpers deliberately keep the existing JSON-shaped API projections while
making PostgreSQL relations the durable authority.  They accept an open
psycopg connection so callers can include all related writes in one transaction.
"""
from __future__ import annotations

import json
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
        cur.execute("""INSERT INTO evolver.release_history
            (release_id, release_kind, version, source_revision, manifest_digest, manifest,
             published_at, published_by, protocol_version, firmware_variant)
            VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)
            ON CONFLICT (release_id) DO NOTHING""", (
            release.get("release_id"), release.get("release_kind"), release.get("version"),
            release.get("source_revision"), release.get("manifest_digest"), _json(release.get("manifest", {})),
            release.get("published_at"), release.get("published_by"), release.get("protocol_version"),
            release.get("firmware_variant")))
    for deployment in state.get("release_deployments", []):
        if not isinstance(deployment, Mapping):
            continue
        cur.execute("""INSERT INTO evolver.release_deployments
            (deployment_id, release_id, controller_id, controller_generation, command_id,
             requested_by, auth_source, requested_at, based_on_release_id, metadata)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (deployment_id) DO NOTHING""", (
            deployment.get("deployment_id"), deployment.get("release_id"), deployment.get("controller_id"),
            deployment.get("controller_generation"), deployment.get("command_id"), deployment.get("requested_by"),
            deployment.get("auth_source"), deployment.get("requested_at"), deployment.get("based_on_release_id"),
            _json(deployment.get("metadata", {}))))
    for event in state.get("release_events", []):
        if not isinstance(event, Mapping):
            continue
        cur.execute("""INSERT INTO evolver.release_deployment_events
            (event_id, deployment_id, event_type, occurred_at, actor, controller_generation, details)
            VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (event_id) DO NOTHING""", (
            event.get("event_id"), event.get("deployment_id"), event.get("event_type"), event.get("occurred_at", event.get("at")),
            event.get("actor"), event.get("controller_generation"), _json(event.get("details", {}))))


def load_calibration(cur: Any) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    cur.execute("SELECT session_id, session FROM evolver.calibration_sessions ORDER BY created_at, session_id")
    sessions = {row["session_id"]: _plain(dict(row["session"])) for row in cur.fetchall()}
    cur.execute("SELECT artifact_id, artifact FROM evolver.calibration_artifacts ORDER BY created_at, artifact_id")
    artifacts = {row["artifact_id"]: _plain(dict(row["artifact"])) for row in cur.fetchall()}
    cur.execute("SELECT event_id, artifact_id, event_type, occurred_at, actor, reason, details FROM evolver.calibration_events ORDER BY occurred_at, event_id")
    events = []
    for row in cur.fetchall():
        event = _plain(dict(row))
        event["id"] = event.pop("event_id")
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
                cur.execute("""INSERT INTO evolver.calibration_sessions (session_id, instrument_id, calibration_type, created_at, session)
                    VALUES (%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT (session_id) DO UPDATE SET session=EXCLUDED.session""", (
                    session_id, session.get("instrument_id"), session.get("calibration_type"), session.get("created_at"), _json(session)))
    artifacts = state.get("calibration_artifacts", {})
    if isinstance(artifacts, Mapping):
        for artifact_id, artifact in artifacts.items():
            if isinstance(artifact, Mapping):
                cur.execute("""INSERT INTO evolver.calibration_artifacts
                    (artifact_id, artifact_digest, instrument_id, vial_position_id, calibration_type, created_at, performed_at, performed_by, artifact)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT (artifact_id) DO UPDATE SET artifact=EXCLUDED.artifact""", (
                    artifact_id, artifact.get("artifact_digest"), artifact.get("instrument_id"), artifact.get("vial_position_id"),
                    artifact.get("calibration_type"), artifact.get("created_at"), artifact.get("performed_at"), artifact.get("performed_by"), _json(artifact)))
    for event in state.get("calibration_events", []):
        if not isinstance(event, Mapping):
            continue
        event_id = event.get("id", event.get("event_id"))
        details = event.get("details", {})
        cur.execute("""INSERT INTO evolver.calibration_events
            (event_id, artifact_id, event_type, occurred_at, actor, reason, details)
            VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (event_id) DO NOTHING""", (
            event_id, event.get("artifact_id"), event.get("event_type", event.get("type", "")),
            event.get("occurred_at", event.get("at")), event.get("actor"), event.get("reason"), _json(details)))


def load_run_resources(cur: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cur.execute("SELECT assignment_id, run_id, sequence, resource_kind, resource_id, assignment_state, assigned_at, released_at, expires_at, assigned_by, reason, supersedes_id, request_id, controller_generation, based_on_revision, sample_reference, details FROM evolver.run_resource_assignments ORDER BY run_id, sequence")
    assignments = []
    for row in cur.fetchall():
        item = _plain(dict(row))
        item["id"] = item.pop("assignment_id")
        details = item.pop("details") or {}
        item["details"] = details
        item.update(details)
        assignments.append(item)
    cur.execute("SELECT event_id, run_id, assignment_id, event_type, occurred_at, actor, reason, details FROM evolver.run_resource_events ORDER BY occurred_at, event_id")
    events = []
    for row in cur.fetchall():
        event = _plain(dict(row))
        event["id"] = event.pop("event_id")
        details = event.pop("details") or {}
        event["details"] = details
        event.update(details)
        events.append(event)
    return assignments, events


def load_od_blank_evidence(cur: Any) -> list[dict[str, Any]]:
    cur.execute("SELECT record_id, controller_id, controller_generation, instrument_id, blank_id, channel_index, raw_adc, captured_at, evidence FROM evolver.od_blank_evidence ORDER BY captured_at, controller_id, record_id")
    records = []
    for row in cur.fetchall():
        record = _plain(dict(row))
        record.update(record.pop("evidence") or {})
        records.append(record)
    return records


def save_od_blank_evidence(cur: Any, state: Mapping[str, Any]) -> None:
    for record in state.get("od_blank_records", []):
        if not isinstance(record, Mapping):
            continue
        reserved = {"record_id", "controller_id", "controller_generation", "instrument_id", "blank_id", "channel_index", "raw_adc", "captured_at"}
        evidence = {key: value for key, value in record.items() if key not in reserved}
        cur.execute("""INSERT INTO evolver.od_blank_evidence
            (record_id, controller_id, controller_generation, instrument_id, blank_id, channel_index, raw_adc, captured_at, evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (controller_id, controller_generation, record_id) DO NOTHING""", (
            record.get("record_id"), record.get("controller_id"), record.get("controller_generation"), record.get("instrument_id"),
            record.get("blank_id"), record.get("channel_index"), record.get("raw_adc"), record.get("captured_at"), _json(evidence)))


def save_run_resources(cur: Any, state: Mapping[str, Any]) -> None:
    for item in state.get("run_resource_assignments", []):
        if not isinstance(item, Mapping):
            continue
        reserved = {"id", "assignment_id", "run_id", "sequence", "resource_kind", "resource_id", "assignment_state",
                    "assigned_at", "released_at", "expires_at", "assigned_by", "reason", "supersedes_id", "request_id",
                    "controller_generation", "based_on_revision", "sample_reference", "details"}
        details = dict(item.get("details", {})) if isinstance(item.get("details"), Mapping) else {}
        details.update({key: value for key, value in item.items() if key not in reserved})
        cur.execute("""INSERT INTO evolver.run_resource_assignments
            (assignment_id, run_id, sequence, resource_kind, resource_id, assignment_state, assigned_at, released_at,
             expires_at, assigned_by, reason, supersedes_id, request_id, controller_generation, based_on_revision, sample_reference, details)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)
            ON CONFLICT (assignment_id) DO UPDATE SET assignment_state=EXCLUDED.assignment_state,
              released_at=EXCLUDED.released_at, reason=EXCLUDED.reason, details=EXCLUDED.details""", (
            item.get("id", item.get("assignment_id")), item.get("run_id"), item.get("sequence"), item.get("resource_kind"),
            item.get("resource_id"), item.get("assignment_state"), item.get("assigned_at"), item.get("released_at"),
            item.get("expires_at"), item.get("assigned_by"), item.get("reason"), item.get("supersedes_id"), item.get("request_id"),
            item.get("controller_generation"), item.get("based_on_revision"), _json(item.get("sample_reference")) if item.get("sample_reference") is not None else None, _json(details)))
    for event in state.get("run_resource_events", []):
        if not isinstance(event, Mapping):
            continue
        reserved = {"id", "event_id", "run_id", "assignment_id", "event_type", "occurred_at", "actor", "reason", "details"}
        details = dict(event.get("details", {})) if isinstance(event.get("details"), Mapping) else {}
        details.update({key: value for key, value in event.items() if key not in reserved})
        cur.execute("""INSERT INTO evolver.run_resource_events
            (event_id, run_id, assignment_id, event_type, occurred_at, actor, reason, details)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT (event_id) DO NOTHING""", (
            event.get("id", event.get("event_id")), event.get("run_id"), event.get("assignment_id"), event.get("event_type"),
            event.get("occurred_at"), event.get("actor"), event.get("reason"), _json(details)))


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
