"""Narrow, non-secret runtime provenance contract for administrator diagnostics."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from .db import DatabaseUnavailableError, connection


def _iso(value: Any) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def metadata() -> dict[str, Any]:
    database: dict[str, Any] = {"initialized_at": None, "initialized_revision": None, "schema_revision": None, "last_migrated_at": None}
    try:
        with connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT key, value FROM system.runtime_metadata WHERE key IN ('initialized_at', 'initialized_revision')")
            values = {row["key"]: row["value"] for row in cur.fetchall()}
            cur.execute("SELECT migration_id, applied_at FROM system.schema_migrations ORDER BY applied_at DESC, migration_id DESC LIMIT 1")
            row = cur.fetchone()
            database.update({"initialized_at": values.get("initialized_at"), "initialized_revision": values.get("initialized_revision"), "schema_revision": row["migration_id"] if row else None, "last_migrated_at": _iso(row["applied_at"]) if row else None})
    except DatabaseUnavailableError:
        pass
    except Exception:
        pass
    services: dict[str, Any] = {}
    service_names = [item.strip() for item in _env("META_WEBUI_RUNTIME_SERVICES").split(",")] if _env("META_WEBUI_RUNTIME_SERVICES") else ["webui"]
    own_service = _env("META_WEBUI_RUNTIME_SERVICE") or "webui"
    for service in filter(None, service_names):
        services[service] = {
            "build_revision": _env("META_WEBUI_BUILD_REVISION"),
            "built_at": _env("META_WEBUI_BUILT_AT"),
            # A process may report its own start time only. Other services
            # share image metadata in Compose but are not observed by WebUI.
            "started_at": _env("META_WEBUI_STARTED_AT") if service == own_service else None,
        }
    return {"observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "database": database, "deployment": {"id": _env("META_WEBUI_DEPLOYMENT_ID"), "deployed_at": _env("META_WEBUI_DEPLOYED_AT"), "source_revision": _env("META_WEBUI_DEPLOYMENT_REVISION")}, "services": services}
