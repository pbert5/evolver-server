"""Portable, credential-free eVOLVER edge recovery archives."""
from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import tarfile
from typing import Any, Mapping

import zstandard

from .store import EdgeStore, EdgeStoreError, Json, _canonical, _decode


ARCHIVE_MEMBER = "recovery.json"
ARCHIVE_FORMAT = "evolver-recovery-v1"


def export_state(store: EdgeStore, destination: str | Path) -> Json:
    """Write a compressed, portable data archive without edge credentials.

    This deliberately exports experiment provenance rather than copying the
    SQLite file: importing it cannot clone the controller identity, binding,
    or credential to a replacement host.
    """
    snapshot = store.recovery_manifest()
    snapshot.update({
        "format": ARCHIVE_FORMAT,
        "telemetry": [record for stream in store.telemetry_streams()
                      for record in store.telemetry_after(stream)],
        "run_revisions": [{"run_id": row["run_id"], "revision": row["revision"],
                            "effective_state": _decode(row["effective_state"]),
                            "effective_state_digest": row["effective_state_digest"], "created_at": row["created_at"]}
                          for row in store._connection.execute("SELECT run_id, revision, effective_state, effective_state_digest, created_at FROM revisions ORDER BY run_id, revision")],
        "cursors": [{"name": row["name"], "value": row["value"]}
                    for row in store._connection.execute("SELECT name, value FROM cursors ORDER BY name")],
    })
    # The recovery manifest already removes binding credentials.  Keep this
    # check near the serialization boundary so future controller fields cannot
    # leak while allowing scientific payloads to use a field named credential.
    controller = snapshot.get("controller", {})
    if "credential" in controller or "credential" in controller.get("binding", {}):
        raise EdgeStoreError("refusing to export a controller credential")
    encoded = _canonical(snapshot).encode("utf-8")
    tar_bytes = BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w") as archive:
        info = tarfile.TarInfo(ARCHIVE_MEMBER)
        info.size = len(encoded)
        info.mode = 0o600
        archive.addfile(info, BytesIO(encoded))
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(zstandard.ZstdCompressor(level=10).compress(tar_bytes.getvalue()))
    return {"archive": str(target), "format": ARCHIVE_FORMAT, "bytes": target.stat().st_size,
            "controller_identity_restored": False, "credential_included": False}


def import_state(store: EdgeStore, source: str | Path) -> Json:
    """Import scientific/runtime history into a *fresh* local state root.

    A destination with experiments is refused rather than silently merging two
    histories.  Its locally generated controller identity remains untouched.
    """
    if store._connection.execute("SELECT 1 FROM bundles LIMIT 1").fetchone() or store._connection.execute("SELECT 1 FROM runs LIMIT 1").fetchone():
        raise EdgeStoreError("recovery import requires a fresh state root; refusing to merge experiment histories")
    raw = zstandard.ZstdDecompressor().decompress(Path(source).read_bytes())
    with tarfile.open(fileobj=BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != 1 or members[0].name != ARCHIVE_MEMBER or not members[0].isfile():
            raise EdgeStoreError("invalid recovery archive layout")
        extracted = archive.extractfile(members[0])
        if extracted is None:
            raise EdgeStoreError("recovery archive is missing its payload")
        try:
            snapshot = json.loads(extracted.read())
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise EdgeStoreError("recovery archive payload is invalid JSON") from error
    _validate(snapshot)
    with store._transaction() as cursor:
        for bundle in snapshot["bundles"]:
            payload = dict(bundle)
            cursor.execute("INSERT INTO bundles(id, digest, payload, accepted_at) VALUES (?, ?, ?, ?)",
                           (payload["id"], payload["digest"], _canonical(payload), snapshot["generated_at"]))
        for run in snapshot["runs"]:
            cursor.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (run["id"], run["bundle_id"], run["controller_id"], _canonical(run["instrument_ids"]), run["state"],
                            run["current_revision"], run["created_at"], run.get("started_at"), run.get("ended_at")))
        for revision in snapshot["run_revisions"]:
            cursor.execute("INSERT INTO revisions VALUES (?, ?, ?, ?, ?)",
                           (revision["run_id"], revision["revision"], _canonical(revision["effective_state"]),
                            revision["effective_state_digest"], revision["created_at"]))
        for patch in snapshot["run_patches"]:
            cursor.execute("INSERT INTO patches VALUES (?, ?, ?, ?)", (patch["run_id"], patch["sequence"], _canonical(patch), patch["effective_revision"]))
        for event in snapshot["run_events"]:
            cursor.execute("INSERT INTO events VALUES (?, ?, ?)", (event["run_id"], event["sequence"], _canonical(event)))
        for telemetry in snapshot["telemetry"]:
            cursor.execute("INSERT INTO telemetry VALUES (?, ?, ?, ?, ?)", (telemetry["stream_id"], telemetry["sequence"],
                           _canonical(telemetry["payload"]), telemetry["digest"], telemetry["captured_at"]))
        for instrument in snapshot["instrument_inventory"]:
            cursor.execute("INSERT INTO instruments VALUES (?, ?, ?, ?, ?, ?)", (instrument["id"], instrument["controller_id"],
                           instrument["instrument_type"], _canonical(instrument["vial_positions"]), _canonical(instrument["capabilities"]), instrument["created_at"]))
            observation = {key: value for key, value in instrument.items() if key not in {"id", "controller_id", "instrument_type", "vial_positions", "capabilities", "created_at", "assigned_runs", "observed_at"}}
            if observation:
                cursor.execute("INSERT INTO instrument_observations VALUES (?, ?, ?)", (instrument["id"], _canonical(observation), instrument.get("observed_at", snapshot["generated_at"])))
        for item in snapshot["cursors"]:
            cursor.execute("INSERT INTO cursors VALUES (?, ?)", (item["name"], str(item["value"])))
    # Recreate append-only spools after the relational import.  The source is
    # verified JSON and subsequent restarts reconcile these exact facts.
    for event in snapshot["run_events"]:
        store._append(store.event_journal_path, event)
    for telemetry in snapshot["telemetry"]:
        store._append(store.telemetry_spool_path, telemetry)
    return {"archive": str(source), "runs": len(snapshot["runs"]), "events": len(snapshot["run_events"]),
            "telemetry": len(snapshot["telemetry"]), "controller_identity_restored": False,
            "controller_id": store.identity()["id"]}


def _validate(snapshot: Any) -> Mapping[str, Any]:
    if not isinstance(snapshot, dict) or snapshot.get("format") != ARCHIVE_FORMAT:
        raise EdgeStoreError("unsupported recovery archive format")
    required_lists = ("bundles", "runs", "run_revisions", "run_patches", "run_events", "telemetry", "instrument_inventory", "cursors")
    if not all(isinstance(snapshot.get(key), list) for key in required_lists):
        raise EdgeStoreError("recovery archive is missing required record lists")
    controller = snapshot.get("controller", {})
    if not isinstance(controller, dict) or "credential" in controller or "credential" in controller.get("binding", {}):
        raise EdgeStoreError("recovery archive unexpectedly contains a controller credential")
    return snapshot
