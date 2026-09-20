"""One-way, operator-invoked import of historical JSON state."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from evolver_server.central_store import PostgresCentralControllerStore


class LegacyImportConflict(RuntimeError):
    """The source digest conflicts with an existing import marker."""


def import_legacy_state(source: str | Path, *, url: str, dry_run: bool = False) -> dict[str, Any]:
    """Validate and optionally import one complete, read-only JSON source."""
    path = Path(source)
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"legacy source is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("legacy source must contain one JSON object")
    summary = {"source": str(path), "source_digest": digest, "controller_count": len(document.get("controllers", {})) if isinstance(document.get("controllers"), dict) else 0, "dry_run": dry_run}
    if dry_run:
        return summary
    store = PostgresCentralControllerStore(url)
    with store._connect() as conn, conn.cursor() as cur:
        try:
            cur.execute("""INSERT INTO evolver.legacy_state_imports(singleton, source_digest, source_path, summary)
                VALUES (true,%s,%s,%s::jsonb) ON CONFLICT (singleton) DO NOTHING RETURNING source_digest""",
                (digest, str(path), json.dumps(summary)))
            reserved = cur.fetchone()
            if reserved is None:
                cur.execute("SELECT source_digest FROM evolver.legacy_state_imports WHERE singleton=true")
                marker = cur.fetchone()
                if marker and marker["source_digest"] != digest:
                    raise LegacyImportConflict("a different legacy source was already imported")
                summary["already_imported"] = True
                return summary
            # The marker and all normalized writes share this caller-owned
            # transaction, so crash/failure cannot leave a marker-less import.
            PostgresCentralControllerStore(url, _connection=conn).save(document, 0)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    summary["already_imported"] = False
    return summary
