"""Central persistence and read-model helpers for eVOLVER release history.

Release identity is immutable.  Deployment requests and their subsequent
protocol/observation facts are separate append-only records: an ACK is never
treated as physical observation.  This module intentionally does not queue a
command or touch controller/instrument state.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from meta_webui_application_backend.db import connection


class ReleaseHistoryError(ValueError):
    """Invalid release-history input."""


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Return the stable digest used to identify the published manifest."""
    encoded = json.dumps(dict(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Release:
    release_id: str
    release_kind: str
    version: str
    source_revision: str
    manifest_digest: str
    manifest: Mapping[str, Any]
    published_at: str
    published_by: str
    protocol_version: str | None = None
    firmware_variant: str | None = None


@dataclass(frozen=True)
class Deployment:
    deployment_id: str
    release_id: str
    controller_id: str
    controller_generation: int
    command_id: str
    requested_by: str
    auth_source: str
    requested_at: str
    based_on_release_id: str | None = None
    metadata: Mapping[str, Any] = frozenset()


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReleaseHistoryError(f"{field} is required")
    return value.strip()


def validate_release(release: Release) -> None:
    if release.release_kind not in {"software", "firmware"}:
        raise ReleaseHistoryError("release_kind must be software or firmware")
    for field in ("release_id", "version", "source_revision", "manifest_digest", "published_at", "published_by"):
        _required_text(getattr(release, field), field)
    if len(release.manifest_digest) != 64 or any(c not in "0123456789abcdef" for c in release.manifest_digest):
        raise ReleaseHistoryError("manifest_digest must be a lowercase SHA-256 digest")
    if not isinstance(release.manifest, Mapping):
        raise ReleaseHistoryError("manifest must be an object")
    if manifest_digest(release.manifest) != release.manifest_digest:
        raise ReleaseHistoryError("manifest_digest does not match manifest")


def validate_deployment(deployment: Deployment) -> None:
    for field in ("deployment_id", "release_id", "controller_id", "command_id", "requested_by", "auth_source", "requested_at"):
        _required_text(getattr(deployment, field), field)
    if deployment.controller_generation <= 0:
        raise ReleaseHistoryError("controller_generation must be positive")
    if not isinstance(deployment.metadata, Mapping):
        raise ReleaseHistoryError("metadata must be an object")


def rollback_eligibility(
    current_release_id: str,
    releases: Sequence[Mapping[str, Any]],
    deployments: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]],
    *,
    controller_id: str,
    controller_generation: int,
) -> dict[str, Any]:
    """Compute rollback candidates from observed facts, never ACKs alone.

    A candidate must be an immutable release previously observed on the same
    controller and generation, and must differ from the current release.
    Failed/rejected deployments do not qualify.  The result is a read model;
    selecting it still requires a new generation-fenced command elsewhere.
    """
    release_map = {str(item.get("release_id")): item for item in releases if isinstance(item, Mapping)}
    observed_deployments: set[str] = set()
    for event in events:
        if event.get("event_type") != "observed":
            continue
        deployment_id = event.get("deployment_id")
        if isinstance(deployment_id, str) and event.get("controller_generation") == controller_generation:
            observed_deployments.add(deployment_id)
    candidates: list[dict[str, Any]] = []
    for deployment in deployments:
        if deployment.get("controller_id") != controller_id or deployment.get("controller_generation") != controller_generation:
            continue
        release_id = deployment.get("release_id")
        if release_id == current_release_id or deployment.get("deployment_id") not in observed_deployments:
            continue
        release = release_map.get(str(release_id))
        if release is not None:
            candidates.append({"release_id": release_id, "version": release.get("version"), "deployment_id": deployment.get("deployment_id"), "eligible": True})
    candidates.sort(key=lambda item: (str(item.get("version")), str(item.get("deployment_id"))), reverse=True)
    return {"current_release_id": current_release_id, "controller_id": controller_id, "controller_generation": controller_generation, "eligible": bool(candidates), "candidates": candidates}


class ReleaseHistoryRepository:
    """Small PostgreSQL repository; every write is insert-only and idempotent."""

    def register_release(self, release: Release) -> None:
        validate_release(release)
        with connection() as conn, conn.cursor() as cur:
            cur.execute("""INSERT INTO evolver.release_history
                (release_id, release_kind, version, source_revision, manifest_digest, manifest,
                 published_at, published_by, protocol_version, firmware_variant)
                VALUES (%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s)
                ON CONFLICT (release_id) DO NOTHING""", (release.release_id, release.release_kind, release.version,
                release.source_revision, release.manifest_digest, json.dumps(dict(release.manifest)), release.published_at,
                release.published_by, release.protocol_version, release.firmware_variant))

    def record_deployment(self, deployment: Deployment) -> None:
        validate_deployment(deployment)
        with connection() as conn, conn.cursor() as cur:
            cur.execute("""INSERT INTO evolver.release_deployments
                (deployment_id, release_id, controller_id, controller_generation, command_id,
                 requested_by, auth_source, requested_at, based_on_release_id, metadata)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                ON CONFLICT (deployment_id) DO NOTHING""", (deployment.deployment_id, deployment.release_id,
                deployment.controller_id, deployment.controller_generation, deployment.command_id, deployment.requested_by,
                deployment.auth_source, deployment.requested_at, deployment.based_on_release_id, json.dumps(dict(deployment.metadata))))

    def append_event(self, *, deployment_id: str, event_type: str, controller_generation: int,
                     occurred_at: str, actor: str | None = None, details: Mapping[str, Any] | None = None,
                     event_id: str | None = None) -> str:
        if event_type not in {"requested", "command_queued", "ack_received", "observed", "failed", "rejected"}:
            raise ReleaseHistoryError("unsupported deployment event type")
        if controller_generation <= 0:
            raise ReleaseHistoryError("controller_generation must be positive")
        event_id = event_id or f"release-event-{uuid4()}"
        with connection() as conn, conn.cursor() as cur:
            cur.execute("""INSERT INTO evolver.release_deployment_events
                (event_id, deployment_id, event_type, occurred_at, actor, controller_generation, details)
                VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT (event_id) DO NOTHING""", (event_id, deployment_id,
                event_type, occurred_at, actor, controller_generation, json.dumps(dict(details or {}))))
        return event_id

    def releases(self) -> list[dict[str, Any]]:
        with connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT release_id, release_kind, version, source_revision, manifest_digest, manifest, published_at, published_by, protocol_version, firmware_variant FROM evolver.release_history ORDER BY published_at, release_id")
            return [dict(row) for row in cur.fetchall()]

    def deployments(self, *, controller_id: str | None = None) -> list[dict[str, Any]]:
        with connection() as conn, conn.cursor() as cur:
            if controller_id is None:
                cur.execute("SELECT deployment_id, release_id, controller_id, controller_generation, command_id, requested_by, auth_source, requested_at, based_on_release_id, metadata FROM evolver.release_deployments ORDER BY requested_at, deployment_id")
            else:
                cur.execute("SELECT deployment_id, release_id, controller_id, controller_generation, command_id, requested_by, auth_source, requested_at, based_on_release_id, metadata FROM evolver.release_deployments WHERE controller_id = %s ORDER BY requested_at, deployment_id", (controller_id,))
            return [dict(row) for row in cur.fetchall()]

    def events(self, *, deployment_id: str | None = None) -> list[dict[str, Any]]:
        with connection() as conn, conn.cursor() as cur:
            if deployment_id is None:
                cur.execute("SELECT event_id, deployment_id, event_type, occurred_at, actor, controller_generation, details FROM evolver.release_deployment_events ORDER BY occurred_at, event_id")
            else:
                cur.execute("SELECT event_id, deployment_id, event_type, occurred_at, actor, controller_generation, details FROM evolver.release_deployment_events WHERE deployment_id = %s ORDER BY occurred_at, event_id", (deployment_id,))
            return [dict(row) for row in cur.fetchall()]
