"""Durable, transport-neutral eVOLVER edge state.

This module deliberately knows no HTTP, WebUI configuration, or hardware
protocol.  It is the small persistence boundary consumed by the controller
runtime, local CLI, and eventual sync client.  JSON values use canonical
encoding so content and effective-state digests are reproducible.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping


Json = dict[str, Any]
SQLITE_BUSY_TIMEOUT_SECONDS = 5.0
SQLITE_BUSY_TIMEOUT_MILLISECONDS = int(SQLITE_BUSY_TIMEOUT_SECONDS * 1000)
from .bundle import (BundleResolutionError, calibration_artifact_digest,
                     calibration_requirement_key, canonical_digest,
                     experiment_purpose, normalize_calibration_requirement,
                     resolve_bundle)


class EdgeStoreError(RuntimeError):
    """Base class for a durable edge-state contract failure."""


class ImmutableBundleError(EdgeStoreError):
    pass


class BundleResolutionError(ImmutableBundleError):
    """A Definition-side bundle cannot be frozen from the supplied evidence."""


class CalibrationPreflightError(EdgeStoreError):
    """A new run cannot safely start with its declared calibration material."""

    def __init__(self, preflight: Mapping[str, Any]):
        self.preflight = dict(preflight)
        super().__init__(f"calibration preflight {self.preflight.get('disposition', 'failed')}")


class StaleRevisionError(EdgeStoreError):
    pass


class StaleGenerationError(EdgeStoreError):
    pass


class CommandInProgressError(EdgeStoreError):
    pass


class LeaseValidationError(EdgeStoreError):
    """A physical command is not owned by the currently active lease."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _decode(raw: str | None) -> Any:
    return json.loads(raw) if raw is not None else None


def _deep_merge(original: Any, change: Any) -> Any:
    if isinstance(original, dict) and isinstance(change, Mapping):
        merged = dict(original)
        for key, value in change.items():
            merged[key] = _deep_merge(merged[key], value) if key in merged else value
        return merged
    return change


class EdgeStore:
    """SQLite-indexed edge state with fsynced append-only journals.

    ``state_root`` is program state, and must be preserved by installers and
    upgrades.  Opening it repeatedly is safe; identity and cursors are loaded
    rather than regenerated.
    """

    def __init__(self, state_root: str | Path):
        self.root = Path(state_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "edge.sqlite3"
        self.event_journal_path = self.root / "run-events.jsonl"
        self.telemetry_spool_path = self.root / "telemetry.jsonl"
        # The hardware IPC listener is a single serialized daemon boundary,
        # but its socket loop runs outside the creator thread.  SQLite still
        # provides the transaction boundary; cross-thread use is restricted
        # to this process-owned connection.
        self._connection = sqlite3.connect(self.db_path, timeout=SQLITE_BUSY_TIMEOUT_SECONDS,
                                           isolation_level=None, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        # CLI enrollment and the sync service can briefly overlap on the same
        # state database.  Wait for that bounded interval before reporting a
        # lock to the caller; the sync loop separately retries an exhausted
        # lock as a transient.
        self._connection.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MILLISECONDS}")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._migrate()
        self._reconcile_append_only_files()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "EdgeStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor = self._connection.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        try:
            yield cursor
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS binding (
              singleton INTEGER PRIMARY KEY CHECK(singleton = 1), controller_id TEXT NOT NULL,
              webui_controller_id TEXT NOT NULL, generation INTEGER NOT NULL,
              server_url TEXT NOT NULL, credential TEXT, status TEXT NOT NULL, bound_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS bundles (
              id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload TEXT NOT NULL, accepted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS runs (
              id TEXT PRIMARY KEY, bundle_id TEXT NOT NULL REFERENCES bundles(id), controller_id TEXT NOT NULL,
              instrument_ids TEXT NOT NULL, state TEXT NOT NULL, current_revision INTEGER NOT NULL,
              created_at TEXT NOT NULL, started_at TEXT, ended_at TEXT);
            CREATE TABLE IF NOT EXISTS revisions (
              run_id TEXT NOT NULL REFERENCES runs(id), revision INTEGER NOT NULL,
              effective_state TEXT NOT NULL, effective_state_digest TEXT NOT NULL, created_at TEXT NOT NULL,
              PRIMARY KEY(run_id, revision));
            CREATE TABLE IF NOT EXISTS patches (
              run_id TEXT NOT NULL REFERENCES runs(id), sequence INTEGER NOT NULL, payload TEXT NOT NULL,
              effective_revision INTEGER NOT NULL, PRIMARY KEY(run_id, sequence));
            CREATE TABLE IF NOT EXISTS events (
              run_id TEXT NOT NULL REFERENCES runs(id), sequence INTEGER NOT NULL, payload TEXT NOT NULL,
              PRIMARY KEY(run_id, sequence));
            CREATE TABLE IF NOT EXISTS commands (
              command_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, status TEXT NOT NULL,
              acknowledgement TEXT, created_at TEXT NOT NULL, completed_at TEXT,
              expected_device TEXT, actual_device TEXT, owner TEXT, operator TEXT,
              requested_device TEXT, requested_owner TEXT, observed_device TEXT, observed_owner TEXT,
              hardware_fingerprint TEXT);
            CREATE TABLE IF NOT EXISTS run_action_executions (
              command_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
              action_id TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL,
              operation TEXT NOT NULL, request TEXT NOT NULL, status TEXT NOT NULL,
              result TEXT, created_at TEXT NOT NULL, completed_at TEXT,
              UNIQUE(run_id, action_id, state, revision));
            CREATE TABLE IF NOT EXISTS telemetry (
              stream_id TEXT NOT NULL, sequence INTEGER NOT NULL, payload TEXT NOT NULL,
              digest TEXT NOT NULL, captured_at TEXT NOT NULL, PRIMARY KEY(stream_id, sequence));
            -- Identity and topology are durable.  Transport and connection state
            -- deliberately live in the latest observation instead of becoming an
            -- accidental hardware identifier.
            CREATE TABLE IF NOT EXISTS instruments (
              id TEXT PRIMARY KEY, controller_id TEXT NOT NULL, instrument_type TEXT NOT NULL,
              vial_positions TEXT NOT NULL, capabilities TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS instrument_observations (
              instrument_id TEXT PRIMARY KEY REFERENCES instruments(id), payload TEXT NOT NULL,
              observed_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS calibration_artifacts (
              id TEXT PRIMARY KEY, artifact_digest TEXT NOT NULL, instrument_id TEXT NOT NULL,
              vial_position TEXT, calibration_type TEXT NOT NULL, method TEXT NOT NULL,
              method_version TEXT NOT NULL, payload TEXT NOT NULL, stored_at TEXT NOT NULL);
            """
        )
        # The command identity columns were added after the initial command
        # journal shipped.  Existing interrupted commands remain inspectable,
        # but cannot be reconciled without identity evidence they never had.
        columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(commands)")}
        for name in ("expected_device", "actual_device", "owner", "operator",
                     "requested_device", "requested_owner", "observed_device",
                     "observed_owner", "hardware_fingerprint"):
            if name not in columns:
                self._connection.execute(f"ALTER TABLE commands ADD COLUMN {name} TEXT")

    def _append(self, path: Path, record: Json) -> None:
        encoded = (_canonical(record) + "\n").encode("utf-8")
        with path.open("ab", buffering=0) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

    def _reconcile_append_only_files(self) -> None:
        """Index valid records which were fsynced before an interrupted DB write.

        A truncated final JSON line is treated as an incomplete write and does
        not get silently interpreted as a fact.  The durable controller enters
        recovery_required so an operator/sync peer can inspect it.
        """
        malformed = False
        for path, kind in ((self.event_journal_path, "event"), (self.telemetry_spool_path, "telemetry")):
            if not path.exists():
                continue
            for raw in path.read_text(encoding="utf-8").splitlines():
                try:
                    record = json.loads(raw)
                    if kind == "event":
                        payload = _canonical(record)
                        existing = self._connection.execute(
                            "SELECT payload FROM events WHERE run_id=? AND sequence=?",
                            (record["run_id"], record["sequence"]),
                        ).fetchone()
                        if existing and existing["payload"] != payload:
                            malformed = True
                            continue
                        if not existing:
                            self._connection.execute("INSERT INTO events(run_id, sequence, payload) VALUES (?, ?, ?)",
                                                     (record["run_id"], record["sequence"], payload))
                    else:
                        existing = self._connection.execute(
                            "SELECT digest FROM telemetry WHERE stream_id=? AND sequence=?",
                            (record["stream_id"], record["sequence"]),
                        ).fetchone()
                        if existing and existing["digest"] != record["digest"]:
                            malformed = True
                            continue
                        if not existing:
                            self._connection.execute("INSERT INTO telemetry VALUES (?, ?, ?, ?, ?)",
                                                     (record["stream_id"], record["sequence"], _canonical(record["payload"]), record["digest"], record["captured_at"]))
                except (KeyError, TypeError, ValueError, sqlite3.IntegrityError):
                    malformed = True
        if malformed:
            identity_row = self._connection.execute("SELECT value FROM meta WHERE key='identity'").fetchone()
            if identity_row:
                identity = _decode(identity_row["value"]); identity["connection_state"] = "recovery_required"
                self._connection.execute("UPDATE meta SET value=? WHERE key='identity'", (_canonical(identity),))

    # Controller and binding -------------------------------------------------
    def identity(self) -> Json:
        row = self._connection.execute("SELECT value FROM meta WHERE key = 'identity'").fetchone()
        if row:
            return _decode(row["value"])
        identity = {
            "id": str(uuid.uuid4()),
            "public_key_fingerprint": hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
            "connection_state": "disconnected",
            "created_at": _now(),
        }
        with self._transaction() as cursor:
            cursor.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('identity', ?)", (_canonical(identity),))
        return _decode(self._connection.execute("SELECT value FROM meta WHERE key = 'identity'").fetchone()["value"])

    def binding(self) -> Json | None:
        row = self._connection.execute("SELECT * FROM binding WHERE singleton = 1").fetchone()
        return dict(row) if row else None

    # Hardware observation --------------------------------------------------
    def record_hardware_observation(self, observation: Mapping[str, Any]) -> Json:
        """Persist the latest edge-local hardware discovery evidence.

        This record intentionally has no instrument identity requirement.  A
        missing device, multiple USB candidates, or an invalid firmware
        identity must remain visible without inventing an identity from a
        transport path.  It is volatile evidence, not a command or an
        assertion that hardware was actuated.
        """
        payload = dict(observation)
        payload.setdefault("observed_at", _now())
        with self._transaction() as cursor:
            cursor.execute(
                "INSERT INTO meta(key, value) VALUES ('hardware_observation', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (_canonical(payload),),
            )
        return payload

    def hardware_observation(self) -> Json | None:
        row = self._connection.execute("SELECT value FROM meta WHERE key='hardware_observation'").fetchone()
        return _decode(row["value"]) if row else None

    def record_instrument_transport(self, instrument_id: str, *, connection_state: str,
                                    transport: Mapping[str, Any], reason: str) -> Json:
        """Update only volatile transport evidence for a known instrument."""
        instrument = self.instrument(instrument_id)
        observation = {key: value for key, value in instrument.items()
                       if key not in {"id", "controller_id", "instrument_type", "vial_positions",
                                      "capabilities", "created_at", "assigned_runs", "observed_at"}}
        observation.update({"connection_state": connection_state, "transport": dict(transport),
                            "transport_evidence": {"reason": reason, "observed": True}})
        with self._transaction() as cursor:
            cursor.execute(
                "INSERT INTO instrument_observations(instrument_id, payload, observed_at) VALUES (?, ?, ?) "
                "ON CONFLICT(instrument_id) DO UPDATE SET payload=excluded.payload, observed_at=excluded.observed_at",
                (instrument_id, _canonical(observation), _now()),
            )
        return self.instrument(instrument_id)

    # Instrument inventory -------------------------------------------------
    def register_instruments(self, inventory: list[Mapping[str, Any]]) -> list[Json]:
        """Record stable instrument identity/topology and its latest observation.

        Callers may rediscover an instrument repeatedly.  Its stable topology
        cannot silently change: a replacement device must receive a new id.
        Volatile facts (port path, connected state, verification results) are
        stored as an observation and may change on every discovery pass.
        """
        controller_id = self.identity()["id"]
        with self._transaction() as cursor:
            for raw in inventory:
                item = dict(raw)
                instrument_id = item.get("id")
                if not isinstance(instrument_id, str) or not instrument_id:
                    raise EdgeStoreError("Instrument requires a stable id")
                item_controller_id = item.get("controller_id", controller_id)
                if item_controller_id != controller_id:
                    raise EdgeStoreError("Instrument must belong to this controller")
                kind = item.get("instrument_type", "unknown")
                positions = item.get("vial_positions", [])
                capabilities = item.get("capabilities", {})
                if not isinstance(kind, str) or not isinstance(positions, list) or not isinstance(capabilities, Mapping):
                    raise EdgeStoreError("Instrument type, vial_positions, and capabilities are invalid")
                existing = cursor.execute("SELECT controller_id, instrument_type, vial_positions FROM instruments WHERE id=?", (instrument_id,)).fetchone()
                if existing and (existing["controller_id"] != controller_id or existing["instrument_type"] != kind
                                 or existing["vial_positions"] != _canonical(positions)):
                    raise EdgeStoreError("Instrument stable identity is already bound to different topology")
                cursor.execute("""INSERT INTO instruments(id, controller_id, instrument_type, vial_positions, capabilities, created_at)
                  VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET capabilities=excluded.capabilities""",
                               (instrument_id, controller_id, kind, _canonical(positions), _canonical(dict(capabilities)), _now()))
                observation = {key: value for key, value in item.items() if key not in {"id", "controller_id", "instrument_type", "vial_positions", "capabilities"}}
                cursor.execute("""INSERT INTO instrument_observations(instrument_id, payload, observed_at) VALUES (?, ?, ?)
                  ON CONFLICT(instrument_id) DO UPDATE SET payload=excluded.payload, observed_at=excluded.observed_at""",
                               (instrument_id, _canonical(observation), _now()))
        return self.list_instruments()

    def list_instruments(self) -> list[Json]:
        """Return durable identity enriched with the most recent volatile observation."""
        rows = self._connection.execute("""SELECT i.*, o.payload AS observation, o.observed_at
          FROM instruments i LEFT JOIN instrument_observations o ON o.instrument_id=i.id ORDER BY i.id""")
        instruments: list[Json] = []
        for row in rows:
            item = {"id": row["id"], "controller_id": row["controller_id"], "instrument_type": row["instrument_type"],
                    "vial_positions": _decode(row["vial_positions"]), "capabilities": _decode(row["capabilities"]),
                    "created_at": row["created_at"]}
            if row["observation"]:
                item.update(_decode(row["observation"]))
                item["observed_at"] = row["observed_at"]
            layout = self.meta(f"physical_layout:{row['id']}")
            if isinstance(layout, dict):
                item["physical_layout"] = layout
            item["assigned_runs"] = [run["id"] for run in self.list_runs() if row["id"] in run["instrument_ids"]
                                     and run["state"] not in {"stopped", "completed", "failed"}]
            instruments.append(item)
        return instruments

    def instrument(self, instrument_id: str) -> Json:
        for item in self.list_instruments():
            if item["id"] == instrument_id:
                return item
        raise KeyError(instrument_id)

    def record_physical_layout(self, *, instrument_id: str, positions: Mapping[int, Mapping[str, Any]],
                               operator: str, device_identity: str) -> Json:
        """Persist commissioning orientation without changing vial identities.

        Layout is durable commissioning evidence, not an inferred sample or
        calibration fact.  It intentionally lives beside the stable topology
        so ordinary discovery observations cannot erase it.
        """
        instrument = self.instrument(instrument_id)
        if not operator or not device_identity:
            raise EdgeStoreError("layout record requires operator and device identity")
        valid = {int(item["position_index"]) for item in instrument["vial_positions"]}
        layout = self.meta(f"physical_layout:{instrument_id}", {})
        if not isinstance(layout, dict): layout = {}
        for channel, value in positions.items():
            if channel not in valid or not isinstance(value, Mapping):
                raise EdgeStoreError("layout record refers to an unknown vial position")
            side = value.get("physical_side")
            if side not in {"left", "right", "unconfirmed"}:
                raise EdgeStoreError("physical_side must be left, right, or unconfirmed")
            method = value.get("method")
            if method not in {"operator_observed", "inferred_two_position_profile"}:
                raise EdgeStoreError("layout method is invalid")
            layout[str(channel)] = {"physical_side": side, "commissioning_evidence": {
                "operator": operator, "timestamp": _now(), "method": method,
                "channel": channel, "device_identity": device_identity}}
        self.set_meta(f"physical_layout:{instrument_id}", layout)
        return {"instrument_id": instrument_id, "physical_layout": layout}

    def set_connection_state(self, state: str) -> Json:
        """Persist the edge's observed central connection state."""
        identity = self.identity()
        identity["connection_state"] = state
        with self._transaction() as cursor:
            cursor.execute("UPDATE meta SET value=? WHERE key='identity'", (_canonical(identity),))
        return identity

    # Immutable calibration material --------------------------------------
    def put_calibration_artifact(self, artifact: Mapping[str, Any]) -> Json:
        """Persist central calibration material without implying actuation.

        Re-delivery of the same id/digest is idempotent.  A changed payload is
        rejected, which keeps a disconnected run pinned to immutable content.
        The caller may use the returned record as the local-storage
        acknowledgement; it is not evidence that a physical calibration ran.
        """
        payload = dict(artifact)
        artifact_id, supplied = payload.get("id"), payload.get("artifact_digest")
        required = (artifact_id, supplied, payload.get("instrument_id"), payload.get("vial_position_id"),
                    payload.get("calibration_type"), payload.get("method"), payload.get("method_version"))
        if not all(isinstance(value, str) and value for value in required):
            raise ImmutableBundleError("calibration artifact requires id, digest, instrument, vial position, type, and method")
        try:
            actual_digest = calibration_artifact_digest(payload)
        except (TypeError, ValueError) as error:
            raise ImmutableBundleError("calibration artifact is not canonical JSON") from error
        if supplied != actual_digest:
            raise ImmutableBundleError("calibration artifact digest does not match canonical content")
        row = self._connection.execute("SELECT artifact_digest, payload FROM calibration_artifacts WHERE id=?", (artifact_id,)).fetchone()
        encoded = _canonical(payload)
        if row:
            if row["artifact_digest"] != supplied or row["payload"] != encoded:
                raise ImmutableBundleError("calibration artifact id is already bound to different immutable content")
            return _decode(row["payload"])
        with self._transaction() as cursor:
            cursor.execute("INSERT INTO calibration_artifacts(id, artifact_digest, instrument_id, vial_position, calibration_type, method, method_version, payload, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (artifact_id, supplied, payload["instrument_id"], payload["vial_position_id"], payload["calibration_type"], payload["method"], payload["method_version"], encoded, _now()))
        return payload

    def calibration_artifacts(self, *, instrument_id: str | None = None) -> list[Json]:
        if instrument_id is None:
            rows = self._connection.execute("SELECT payload FROM calibration_artifacts ORDER BY stored_at")
        else:
            rows = self._connection.execute("SELECT payload FROM calibration_artifacts WHERE instrument_id=? ORDER BY stored_at", (instrument_id,))
        return [_decode(row["payload"]) for row in rows]

    def calibration_preflight(self, references: Any, *, requirements: Any = None) -> Json:
        """Classify calibration readiness without changing state or hardware.

        Missing artifacts are a recoverable ``blocked`` state: the controller
        can continue existing offline runs and await the immutable delivery.
        A malformed reference, digest conflict, or target mismatch is a
        ``hard_reject`` because starting would bind a run to the wrong physical
        calibration.  ``eligible`` is the only start-safe disposition.
        """
        missing: list[str] = []
        optional_missing: list[str] = []
        digest_mismatches: list[str] = []
        target_mismatches: list[str] = []
        invalid_references: list[str] = []
        if not isinstance(references, list):
            return {"disposition": "hard_reject", "eligible": False, "blocked": False,
                    "hard_reject": True, "missing_artifact_ids": missing,
                    "optional_missing_artifact_ids": optional_missing,
                    "mismatched_artifact_ids": digest_mismatches,
                    "target_mismatched_artifact_ids": target_mismatches,
                    "invalid_references": ["calibration_references must be a list"]}
        declared: dict[tuple[Any, ...], Json] | None = None
        if requirements is not None:
            if not isinstance(requirements, list):
                invalid_references.append("calibration_requirements must be a list")
            else:
                try:
                    normalized = [normalize_calibration_requirement(item, index, error_type=BundleResolutionError)
                                  for index, item in enumerate(requirements)]
                except BundleResolutionError as error:
                    invalid_references.append(str(error))
                else:
                    declared = {calibration_requirement_key(item): item for item in normalized}
                    if len(declared) != len(normalized):
                        invalid_references.append("calibration requirements must not duplicate a capability target")
        local = {item["id"]: item for item in self.calibration_artifacts()
                 if isinstance(item, dict) and isinstance(item.get("id"), str)}
        required = ("artifact_id", "artifact_digest", "instrument_id", "vial_position_id",
                    "calibration_type", "method", "method_version")
        declared_references: set[tuple[Any, ...]] = set()
        seen: dict[str, str] = {}
        seen_reference_keys: set[tuple[Any, ...]] = set()
        for index, reference in enumerate(references):
            if not isinstance(reference, Mapping):
                invalid_references.append(f"reference[{index}] is not an object")
                continue
            item = dict(reference)
            if any(not isinstance(item.get(field), str) or not item[field] for field in required):
                invalid_references.append(f"reference[{index}] lacks immutable calibration identity")
                continue
            is_required = item.get("required", True)
            if not isinstance(is_required, bool):
                invalid_references.append(f"reference[{index}] must declare required as true or false")
                continue
            if declared is not None:
                key = calibration_requirement_key(item)
                declaration = declared.get(key)
                if not isinstance(item.get("capability"), str) or declaration is None or declaration["required"] != is_required:
                    invalid_references.append(f"reference[{index}] does not match a declared calibration capability")
                    continue
                if key in seen_reference_keys:
                    invalid_references.append(f"reference[{index}] duplicates a calibration capability")
                    continue
                seen_reference_keys.add(key)
                declared_references.add(key)
            artifact_id, digest = item["artifact_id"], item["artifact_digest"]
            if artifact_id in seen:
                detail = "different digest" if seen[artifact_id] != digest else "duplicate reference"
                invalid_references.append(f"reference[{index}] reuses {artifact_id} with {detail}")
                continue
            seen[artifact_id] = digest
            artifact = local.get(artifact_id)
            if artifact is None:
                missing.append(artifact_id)
                if not is_required:
                    optional_missing.append(artifact_id)
                continue
            if artifact.get("artifact_digest") != digest:
                digest_mismatches.append(artifact_id)
                continue
            if any(artifact.get(field) != item[field] for field in required[2:]):
                target_mismatches.append(artifact_id)
        if declared is not None:
            absent = [item["capability"] for key, item in declared.items()
                      if item["required"] and key not in declared_references]
            invalid_references.extend(f"required calibration reference is absent for {capability}" for capability in absent)
        required_missing = [artifact_id for artifact_id in missing if artifact_id not in optional_missing]
        hard_reject = bool(invalid_references or digest_mismatches or target_mismatches)
        blocked = bool(required_missing) and not hard_reject
        return {"disposition": "hard_reject" if hard_reject else "blocked" if blocked else "eligible",
                "eligible": not hard_reject and not blocked, "blocked": blocked, "hard_reject": hard_reject,
                "missing_artifact_ids": missing, "mismatched_artifact_ids": digest_mismatches,
                "optional_missing_artifact_ids": optional_missing,
                "target_mismatched_artifact_ids": target_mismatches,
                "invalid_references": invalid_references}

    def calibration_bundle_preflight(self, bundle_id: str) -> Json:
        """Evaluate a stored immutable bundle before creating a new run."""
        bundle = self.bundle(bundle_id)
        return self.calibration_preflight(bundle.get("calibration_references", []),
                                          requirements=bundle.get("calibration_requirements")
                                          if "calibration_requirements" in bundle else None)

    def bind(self, *, webui_controller_id: str, server_url: str, credential: str, generation: int = 1,
             status: str = "active", force_adoption: bool = False) -> Json:
        """Persist a server identity binding; changing central identity requires fencing."""
        identity = self.identity()
        current = self.binding()
        if current and current["webui_controller_id"] != webui_controller_id and not force_adoption:
            raise StaleGenerationError("central identity differs; explicit forced adoption is required")
        if current and generation < current["generation"]:
            raise StaleGenerationError("binding generation cannot decrease")
        if current and current["webui_controller_id"] != webui_controller_id and generation <= current["generation"]:
            raise StaleGenerationError("adoption must increment controller generation")
        result = {"controller_id": identity["id"], "webui_controller_id": webui_controller_id,
                  "generation": generation, "server_url": server_url, "credential": credential,
                  "status": status, "bound_at": _now()}
        with self._transaction() as cursor:
            cursor.execute("""INSERT INTO binding(singleton, controller_id, webui_controller_id, generation, server_url, credential, status, bound_at)
              VALUES(1, :controller_id, :webui_controller_id, :generation, :server_url, :credential, :status, :bound_at)
              ON CONFLICT(singleton) DO UPDATE SET controller_id=excluded.controller_id, webui_controller_id=excluded.webui_controller_id,
              generation=excluded.generation, server_url=excluded.server_url, credential=excluded.credential, status=excluded.status, bound_at=excluded.bound_at""", result)
        return self.binding() or result

    # Immutable bundles and revisions --------------------------------------
    def put_bundle(self, bundle: Mapping[str, Any]) -> Json:
        payload = dict(bundle)
        bundle_id, supplied_digest = payload.get("id"), payload.pop("digest", None)
        if not bundle_id or not supplied_digest:
            raise ImmutableBundleError("ExperimentBundle requires id and digest")
        digest = canonical_digest(payload)
        if digest != supplied_digest:
            raise ImmutableBundleError("ExperimentBundle digest does not match canonical content")
        payload["digest"] = supplied_digest
        row = self._connection.execute("SELECT digest, payload FROM bundles WHERE id = ?", (bundle_id,)).fetchone()
        if row:
            if row["digest"] != supplied_digest or row["payload"] != _canonical(payload):
                raise ImmutableBundleError("ExperimentBundle id is already bound to different immutable content")
            return _decode(row["payload"])
        with self._transaction() as cursor:
            cursor.execute("INSERT INTO bundles(id, digest, payload, accepted_at) VALUES (?, ?, ?, ?)",
                           (bundle_id, supplied_digest, _canonical(payload), _now()))
        return payload

    def bundle(self, bundle_id: str) -> Json:
        row = self._connection.execute("SELECT payload FROM bundles WHERE id = ?", (bundle_id,)).fetchone()
        if not row:
            raise KeyError(bundle_id)
        value = _decode(row["payload"])
        # Old immutable bundles may not contain purpose.  Add the compatibility
        # view only; the stored payload and digest remain byte-for-byte intact.
        value.setdefault("purpose", experiment_purpose(value.get("purpose")))
        return value

    def create_run(self, *, run_id: str, bundle_id: str, instrument_ids: list[str], state: str = "ready",
                   effective_state: Mapping[str, Any] | None = None) -> Json:
        if not instrument_ids:
            raise EdgeStoreError("ExperimentRun requires at least one Instrument")
        self.bundle(bundle_id)
        preflight = self.calibration_bundle_preflight(bundle_id)
        if not preflight["eligible"]:
            raise CalibrationPreflightError(preflight)
        controller_id = self.identity()["id"]
        initial_state = dict(effective_state or {"bundle_id": bundle_id, "runtime_parameters": {}, "state": state})
        digest, created = canonical_digest(initial_state), _now()
        with self._transaction() as cursor:
            try:
                cursor.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?, 0, ?, NULL, NULL)",
                               (run_id, bundle_id, controller_id, _canonical(instrument_ids), state, created))
                cursor.execute("INSERT INTO revisions VALUES (?, 0, ?, ?, ?)",
                               (run_id, _canonical(initial_state), digest, created))
            except sqlite3.IntegrityError as error:
                raise EdgeStoreError(f"run already exists or bundle absent: {run_id}") from error
        self.append_event(run_id=run_id, event_type="run_created", revision=0, details={"bundle_id": bundle_id})
        return self.run(run_id)

    def run(self, run_id: str) -> Json:
        row = self._connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not row:
            raise KeyError(run_id)
        value = dict(row); value["instrument_ids"] = _decode(value["instrument_ids"])
        value["effective_state"] = self.revision(run_id)["effective_state"]
        value["effective_state_digest"] = self.revision(run_id)["effective_state_digest"]
        value["purpose"] = experiment_purpose(self.bundle(value["bundle_id"]).get("purpose"))
        return value

    def list_runs(self) -> list[Json]:
        return [self.run(row["id"]) for row in self._connection.execute("SELECT id FROM runs ORDER BY created_at")]

    def revision(self, run_id: str, revision: int | None = None) -> Json:
        if revision is None:
            row = self._connection.execute("SELECT current_revision FROM runs WHERE id=?", (run_id,)).fetchone()
            if not row: raise KeyError(run_id)
            revision = row["current_revision"]
        row = self._connection.execute("SELECT * FROM revisions WHERE run_id=? AND revision=?", (run_id, revision)).fetchone()
        if not row: raise KeyError((run_id, revision))
        value = dict(row); value["effective_state"] = _decode(value["effective_state"]); return value

    def apply_patch(self, patch: Mapping[str, Any]) -> Json:
        value = dict(patch); run_id = value.get("run_id")
        if not run_id or "based_on_revision" not in value or "change" not in value:
            raise EdgeStoreError("RunPatch requires run_id, based_on_revision, and change")
        with self._transaction() as cursor:
            run = cursor.execute("SELECT current_revision FROM runs WHERE id=?", (run_id,)).fetchone()
            if not run: raise KeyError(run_id)
            if value["based_on_revision"] != run["current_revision"]:
                raise StaleRevisionError(f"patch based on {value['based_on_revision']}, current revision is {run['current_revision']}")
            current = cursor.execute("SELECT effective_state FROM revisions WHERE run_id=? AND revision=?", (run_id, run["current_revision"])).fetchone()
            next_revision = run["current_revision"] + 1
            next_state = _deep_merge(_decode(current["effective_state"]), value["change"])
            value.setdefault("id", str(uuid.uuid4())); value.setdefault("sequence", next_revision)
            value.setdefault("requested_at", _now()); value["effective_revision"] = next_revision
            cursor.execute("INSERT INTO patches(run_id, sequence, payload, effective_revision) VALUES (?, ?, ?, ?)",
                           (run_id, value["sequence"], _canonical(value), next_revision))
            cursor.execute("INSERT INTO revisions VALUES (?, ?, ?, ?, ?)",
                           (run_id, next_revision, _canonical(next_state), canonical_digest(next_state), _now()))
            cursor.execute("UPDATE runs SET current_revision=? WHERE id=?", (next_revision, run_id))
        return self.revision(run_id)

    def transition_run(self, *, run_id: str, state: str, based_on_revision: int,
                       command_id: str | None = None) -> Json:
        """Revision-safe lifecycle transition used by local and central commands."""
        event_for_state = {"running": "run_started", "paused": "run_paused", "ready": "run_resumed",
                           "stopped": "run_stopped"}
        revision = self.apply_patch({"run_id": run_id, "based_on_revision": based_on_revision,
                                     "patch_kind": "resume" if state == "running" else state,
                                     "change": {"state": state}})
        now = _now()
        with self._transaction() as cursor:
            assignments = ["state=?"]
            parameters: list[Any] = [state]
            if state == "running": assignments.append("started_at=COALESCE(started_at, ?)"); parameters.append(now)
            if state in {"stopped", "completed", "failed"}: assignments.append("ended_at=?"); parameters.append(now)
            parameters.append(run_id)
            cursor.execute(f"UPDATE runs SET {', '.join(assignments)} WHERE id=?", parameters)
        self.append_event(run_id=run_id, event_type=event_for_state.get(state, "condition_reached"),
                          revision=revision["revision"], details={"state": state}, causation_command_id=command_id)
        return self.run(run_id)

    # Journal, dedupe, telemetry -------------------------------------------
    def append_event(self, *, run_id: str, event_type: str, revision: int, details: Mapping[str, Any] | None = None,
                     causation_command_id: str | None = None) -> Json:
        row = self._connection.execute("SELECT COALESCE(MAX(sequence), 0) + 1 AS seq FROM events WHERE run_id=?", (run_id,)).fetchone()
        event = {"id": str(uuid.uuid4()), "run_id": run_id, "sequence": row["seq"], "event_type": event_type,
                 "occurred_at": _now(), "revision": revision, "details": dict(details or {})}
        if causation_command_id: event["causation_command_id"] = causation_command_id
        self._append(self.event_journal_path, event)
        with self._transaction() as cursor:
            cursor.execute("INSERT INTO events(run_id, sequence, payload) VALUES (?, ?, ?)",
                           (run_id, event["sequence"], _canonical(event)))
        return event

    def events_after(self, run_id: str, sequence: int = 0) -> list[Json]:
        return [_decode(row["payload"]) for row in self._connection.execute(
            "SELECT payload FROM events WHERE run_id=? AND sequence>? ORDER BY sequence", (run_id, sequence))]

    def all_events(self) -> list[Json]:
        return [_decode(row["payload"]) for row in self._connection.execute("SELECT payload FROM events ORDER BY run_id, sequence")]

    def event_streams(self) -> list[str]:
        """Stable run event stream identifiers, suitable for cursor sync."""
        return [row["run_id"] for row in self._connection.execute("SELECT DISTINCT run_id FROM events ORDER BY run_id")]

    def execute_command(self, command: Mapping[str, Any], handler: Callable[[], Json]) -> Json:
        """Deduplicate a command durably. Handler must be deterministic/idempotent.

        A completed acknowledgement is retained across process restarts.  An
        interrupted in-flight command is deliberately not replayed blindly;
        callers can reconcile it using the journal and return recovery_required.
        """
        command_id = command.get("command_id") or command.get("id")
        if not command_id: raise EdgeStoreError("Command requires command_id")
        binding = self.binding()
        if binding and command.get("controller_generation") != binding["generation"]:
            raise StaleGenerationError("command generation is not the active binding generation")
        with self._transaction() as cursor:
            existing = cursor.execute("SELECT status, acknowledgement FROM commands WHERE command_id=?", (command_id,)).fetchone()
            if existing and existing["status"] == "completed": return _decode(existing["acknowledgement"])
            if existing: raise CommandInProgressError(f"command {command_id} was interrupted; reconcile before retry")
            cursor.execute("""INSERT INTO commands
                (command_id, generation, status, created_at, expected_device,
                 actual_device, owner, operator, requested_device, requested_owner,
                 observed_device, observed_owner, hardware_fingerprint)
                VALUES (?, ?, 'in_progress', ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)""",
                (command_id, command.get("controller_generation", 0), _now(),
                 command.get("expected_device"), command.get("actual_device"),
                 command.get("owner"), command.get("operator"),
                 command.get("requested_device"), command.get("requested_owner")))
        acknowledgement = handler()
        with self._transaction() as cursor:
            evidence = acknowledgement.get("observed_evidence", {}) if isinstance(acknowledgement, Mapping) else {}
            observed_device = evidence.get("device_id") if isinstance(evidence, Mapping) else None
            observed_owner = evidence.get("owner_id") if isinstance(evidence, Mapping) else None
            fingerprint = evidence.get("hardware_fingerprint") if isinstance(evidence, Mapping) else None
            cursor.execute("""UPDATE commands SET status='completed', acknowledgement=?, completed_at=?,
                             observed_device=?, observed_owner=?, hardware_fingerprint=?
                             WHERE command_id=?""",
                           (_canonical(acknowledgement), _now(), observed_device, observed_owner,
                            _canonical(fingerprint) if fingerprint is not None else None, command_id))
        return acknowledgement

    def acknowledge_command(self, command: Mapping[str, Any], acknowledgement: Json) -> Json:
        """Durably record a terminal rejection, including a fenced request."""
        command_id = command.get("command_id") or command.get("id")
        if not command_id:
            raise EdgeStoreError("Command requires command_id")
        with self._transaction() as cursor:
            existing = cursor.execute("SELECT status, acknowledgement FROM commands WHERE command_id=?", (command_id,)).fetchone()
            if existing and existing["status"] == "completed":
                return _decode(existing["acknowledgement"])
            if existing:
                raise CommandInProgressError(f"command {command_id} was interrupted; reconcile before retry")
            now = _now()
            cursor.execute("INSERT INTO commands(command_id, generation, status, acknowledgement, created_at, completed_at) VALUES (?, ?, 'completed', ?, ?, ?)",
                           (command_id, command.get("controller_generation", 0), _canonical(acknowledgement), now, now))
        return acknowledgement

    @staticmethod
    def _command_identity(value: Mapping[str, Any], *, require_generation: bool = True) -> dict[str, Any]:
        """Validate the stable identity fields used by timeout reconciliation."""
        required = ("requested_device", "requested_owner", "observed_device", "observed_owner", "operator")
        # Legacy callers and rows use expected/actual/owner.  Normalize them at
        # the boundary without pretending that requested data was observed.
        value = dict(value)
        value.setdefault("requested_device", value.get("expected_device"))
        value.setdefault("requested_owner", value.get("owner"))
        value.setdefault("observed_device", value.get("actual_device"))
        value.setdefault("observed_owner", value.get("owner"))
        if any(not isinstance(value.get(key), str) or not value[key].strip() for key in required):
            raise EdgeStoreError("command identity evidence requires non-blank strings")
        generation = value.get("generation", value.get("controller_generation"))
        if require_generation and (isinstance(generation, bool) or not isinstance(generation, int) or generation < 0):
            raise EdgeStoreError("command identity evidence requires a valid generation")
        return {"requested_device": value["requested_device"].strip(),
                "requested_owner": value["requested_owner"].strip(),
                "observed_device": value["observed_device"].strip(),
                "observed_owner": value["observed_owner"].strip(),
                "operator": value["operator"].strip(),
                "generation": generation}

    def inspect_command(self, command_id: str) -> Json | None:
        """Read one durable command record without changing edge state."""
        if not isinstance(command_id, str) or not command_id.strip():
            raise EdgeStoreError("Command requires a non-blank command_id")
        row = self._connection.execute("SELECT * FROM commands WHERE command_id=?", (command_id,)).fetchone()
        if not row:
            return None
        record = dict(row)
        record["acknowledgement"] = _decode(record["acknowledgement"])
        return record

    def reconcile_command(self, command_id: str, evidence: Mapping[str, Any] | None = None,
                          *, final_identity: Mapping[str, Any] | None = None) -> Json:
        """Complete exactly one interrupted command from matching identity evidence.

        This is deliberately a database-only operation: it has no callback and
        therefore cannot issue, retry, or imply a physical command.
        """
        if not isinstance(command_id, str) or not command_id.strip():
            raise EdgeStoreError("Command requires a non-blank command_id")
        if evidence is not None and final_identity is not None:
            raise EdgeStoreError("provide command identity evidence only once")
        evidence = final_identity if final_identity is not None else evidence
        if not isinstance(evidence, Mapping):
            raise EdgeStoreError("command identity evidence must be a mapping")
        identity = self._command_identity(evidence)
        with self._transaction() as cursor:
            row = cursor.execute("SELECT * FROM commands WHERE command_id=?", (command_id,)).fetchone()
            if not row:
                raise EdgeStoreError(f"command {command_id} does not exist")
            if row["status"] != "in_progress":
                raise EdgeStoreError(f"command {command_id} is already terminal")
            if row["generation"] != identity["generation"]:
                raise StaleGenerationError("command generation does not match final identity evidence")
            row_values = {"requested_device": row["requested_device"] or row["expected_device"],
                          "requested_owner": row["requested_owner"] or row["owner"],
                          "observed_device": row["observed_device"] or row["actual_device"],
                          "observed_owner": row["observed_owner"] or row["owner"],
                          "operator": row["operator"]}
            for key in ("requested_device", "requested_owner", "observed_device", "observed_owner", "operator"):
                if row_values[key] != identity[key]:
                    raise EdgeStoreError(f"command {key} does not match final identity evidence")
            acknowledgement = {"command_id": row["command_id"], "generation": row["generation"],
                               **row_values, "reconciled_after_timeout": True}
            if not row["requested_device"] and not row["requested_owner"]:
                # Preserve the response shape of pre-migration callers while
                # exposing explicit fields for new command records.
                acknowledgement = {"command_id": row["command_id"], "generation": row["generation"],
                                   "expected_device": row["expected_device"], "actual_device": row["actual_device"],
                                   "owner": row["owner"], "operator": row["operator"],
                                   "reconciled_after_timeout": True}
            cursor.execute("UPDATE commands SET status='completed', acknowledgement=?, completed_at=? WHERE command_id=? AND status='in_progress'",
                           (_canonical(acknowledgement), _now(), command_id))
        return acknowledgement

    def quarantine_command(self, command_id: str, *, operator: str, reason_kind: str,
                           requested_identity: Mapping[str, Any] | None = None,
                           observed_identity: Mapping[str, Any] | None = None,
                           hardware_fingerprint: Mapping[str, Any] | None = None,
                           protocol_ack_observed: bool = False) -> Json:
        """Terminalize one ambiguous command using SQLite only.

        This method has no callback or hardware dependency and is intentionally
        separate from successful identity reconciliation.  It cannot claim an
        ACK, retry a write, clear identity, or actuate hardware.
        """
        if not isinstance(command_id, str) or not command_id.strip():
            raise EdgeStoreError("Command requires a non-blank command_id")
        if not isinstance(operator, str) or not operator.strip():
            raise EdgeStoreError("operator attribution is required")
        if not isinstance(reason_kind, str) or not reason_kind.strip():
            raise EdgeStoreError("reason_kind is required")
        if protocol_ack_observed:
            raise EdgeStoreError("quarantine cannot assert an unproven protocol ACK")
        requested_identity = requested_identity or {}
        observed_identity = observed_identity or {}
        with self._transaction() as cursor:
            row = cursor.execute("SELECT * FROM commands WHERE command_id=?", (command_id,)).fetchone()
            if not row:
                raise EdgeStoreError(f"command {command_id} does not exist")
            if row["status"] != "in_progress":
                raise EdgeStoreError(f"command {command_id} is already terminal")
            acknowledgement = {
                "command_id": command_id, "generation": row["generation"],
                "disposition": "quarantined", "reason_kind": reason_kind.strip(),
                "operator": operator.strip(),
                "requested_device": requested_identity.get("device_id"),
                "requested_owner": requested_identity.get("owner_id"),
                "observed_device": observed_identity.get("device_id"),
                "observed_owner": observed_identity.get("owner_id"),
                "hardware_fingerprint": dict(hardware_fingerprint or {}),
                "reconciled_after_timeout": False,
                "protocol_ack_observed": False,
                "physical_retry_performed": False,
            }
            cursor.execute("""UPDATE commands SET status='quarantined', acknowledgement=?,
                             completed_at=?, requested_device=COALESCE(?, requested_device, expected_device),
                             requested_owner=COALESCE(?, requested_owner, owner),
                             observed_device=?, observed_owner=?, hardware_fingerprint=?
                             WHERE command_id=? AND status='in_progress'""",
                           (_canonical(acknowledgement), _now(), requested_identity.get("device_id"),
                            requested_identity.get("owner_id"), observed_identity.get("device_id"),
                            observed_identity.get("owner_id"), _canonical(dict(hardware_fingerprint or {})), command_id))
        return acknowledgement

    def spool_telemetry(self, *, stream_id: str, sequence: int, payload: Mapping[str, Any], captured_at: str | None = None) -> Json:
        record = {"stream_id": stream_id, "sequence": sequence, "payload": dict(payload), "captured_at": captured_at or _now()}
        record["digest"] = canonical_digest(record)
        existing = self._connection.execute("SELECT digest FROM telemetry WHERE stream_id=? AND sequence=?", (stream_id, sequence)).fetchone()
        if existing:
            if existing["digest"] != record["digest"]: raise EdgeStoreError("telemetry sequence conflicts with existing data")
            return record
        self._append(self.telemetry_spool_path, record)
        with self._transaction() as cursor:
            cursor.execute("INSERT INTO telemetry VALUES (?, ?, ?, ?, ?)",
                           (stream_id, sequence, _canonical(record["payload"]), record["digest"], record["captured_at"]))
        return record

    def telemetry_after(self, stream_id: str, sequence: int = 0) -> list[Json]:
        rows = self._connection.execute("SELECT * FROM telemetry WHERE stream_id=? AND sequence>? ORDER BY sequence", (stream_id, sequence))
        return [{"stream_id": r["stream_id"], "sequence": r["sequence"], "payload": _decode(r["payload"]), "digest": r["digest"], "captured_at": r["captured_at"]} for r in rows]

    def telemetry_streams(self) -> list[str]:
        return [row["stream_id"] for row in self._connection.execute("SELECT DISTINCT stream_id FROM telemetry ORDER BY stream_id")]

    def command_acknowledgements(self) -> list[Json]:
        return [_decode(row["acknowledgement"]) for row in self._connection.execute(
            "SELECT acknowledgement FROM commands WHERE status IN ('completed','quarantined') AND acknowledgement IS NOT NULL ORDER BY completed_at")]

    def run_action(self, command_id: str) -> Json | None:
        row = self._connection.execute("SELECT * FROM run_action_executions WHERE command_id=?", (command_id,)).fetchone()
        if not row:
            return None
        value = dict(row)
        value["request"] = _decode(value["request"])
        value["result"] = _decode(value["result"])
        return value

    def record_run_action(self, *, command_id: str, run_id: str, action_id: str,
                          state: str, revision: int, operation: str,
                          request: Mapping[str, Any], status: str = "pending",
                          result: Mapping[str, Any] | None = None) -> Json:
        now = _now()
        encoded_request = _canonical(dict(request))
        encoded_result = _canonical(dict(result)) if result is not None else None
        with self._transaction() as cursor:
            existing = cursor.execute("SELECT * FROM run_action_executions WHERE command_id=?", (command_id,)).fetchone()
            if existing:
                return self.run_action(command_id)  # type: ignore[return-value]
            try:
                cursor.execute("""INSERT INTO run_action_executions
                    (command_id, run_id, action_id, state, revision, operation, request, status, result, created_at, completed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (command_id, run_id, action_id, state, revision, operation, encoded_request,
                     status, encoded_result, now, now if result is not None else None))
            except sqlite3.IntegrityError as error:
                raise EdgeStoreError("run action identity already belongs to another action") from error
        return self.run_action(command_id)  # type: ignore[return-value]

    def complete_run_action(self, command_id: str, *, status: str,
                            result: Mapping[str, Any] | None = None) -> Json:
        with self._transaction() as cursor:
            cursor.execute("UPDATE run_action_executions SET status=?, result=?, completed_at=? WHERE command_id=?",
                           (status, _canonical(dict(result)) if result is not None else None, _now(), command_id))
            if cursor.rowcount != 1:
                raise KeyError(command_id)
        return self.run_action(command_id)  # type: ignore[return-value]

    def run_actions(self, run_id: str) -> list[Json]:
        rows = self._connection.execute("SELECT command_id FROM run_action_executions WHERE run_id=? ORDER BY created_at", (run_id,))
        return [self.run_action(row["command_id"]) for row in rows]  # type: ignore[list-item]

    def set_cursor(self, name: str, value: int | str) -> None:
        with self._transaction() as cursor:
            cursor.execute("INSERT INTO cursors VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", (name, str(value)))

    def cursor(self, name: str, default: int | str = 0) -> str:
        row = self._connection.execute("SELECT value FROM cursors WHERE name=?", (name,)).fetchone()
        return row["value"] if row else str(default)

    def set_meta(self, key: str, value: Any) -> None:
        """Persist small controller-local settings, never credentials in output."""
        with self._transaction() as cursor:
            cursor.execute("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                           (key, _canonical(value)))

    def meta(self, key: str, default: Any = None) -> Any:
        row = self._connection.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return _decode(row["value"]) if row else default

    def set_control_lease(self, *, lease_token: str, owner: str, generation: int,
                          expires_at: str) -> None:
        """Persist the edge copy of a central lease without storing its token."""
        if not all(isinstance(value, str) and value for value in (lease_token, owner, expires_at)):
            raise LeaseValidationError("lease token, owner, and expiry are required")
        value = {"token_digest": hashlib.sha256(lease_token.encode()).hexdigest(),
                 "owner": owner, "generation": generation, "expires_at": expires_at}
        self.set_meta("control_lease", value)

    def acquire_local_commissioning_lease(self, owner: str, ttl_seconds: int = 900) -> Json:
        """Issue a bounded host-local maintenance lease for the IPC service."""
        if not owner or not isinstance(owner, str):
            raise LeaseValidationError("commissioning lease owner is required")
        if not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= 86400:
            raise LeaseValidationError("commissioning lease TTL must be between 1 and 86400 seconds")
        active = [run for run in self.list_runs() if run.get("state") in {"running", "paused", "stopping"}]
        if active:
            raise LeaseValidationError("commissioning lease is unavailable while a run owns hardware")
        current = self.meta("control_lease")
        if isinstance(current, dict):
            try:
                if datetime.fromisoformat(str(current["expires_at"]).replace("Z", "+00:00")) > datetime.now(UTC):
                    raise LeaseValidationError("hardware lease is already held")
            except (KeyError, ValueError, TypeError):
                pass
        binding = self.binding() or {}
        generation = int(binding.get("generation", 0))
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(UTC).timestamp() + ttl_seconds)
        expires_at = datetime.fromtimestamp(expires, UTC).isoformat()
        self.set_control_lease(lease_token=token, owner=owner, generation=generation, expires_at=expires_at)
        lease = {"lease_id": str(uuid.uuid4()), "owner": owner, "purpose": "commissioning/manual_maintenance",
                 "generation": generation, "expires_at": expires_at, "status": "active", "token": token}
        self.set_meta("commissioning_lease", {key: value for key, value in lease.items() if key != "token"})
        return lease

    def local_commissioning_lease_status(self) -> Json:
        lease = self.meta("commissioning_lease")
        if not isinstance(lease, dict):
            return {"status": "none"}
        try:
            expired = datetime.fromisoformat(str(lease["expires_at"]).replace("Z", "+00:00")) <= datetime.now(UTC)
        except (KeyError, ValueError, TypeError):
            expired = True
        return {**lease, "status": "expired" if expired else lease.get("status", "active")}

    def release_local_commissioning_lease(self, owner: str) -> Json:
        lease = self.local_commissioning_lease_status()
        if lease.get("status") == "none": return lease
        if lease.get("owner") != owner: raise LeaseValidationError("commissioning lease owner mismatch")
        self.set_meta("commissioning_lease", {**lease, "status": "released", "released_at": _now()})
        self.set_meta("control_lease", None)
        return {**lease, "status": "released"}

    def validate_control_lease(self, *, lease_token: str | None, owner: str | None,
                               generation: int) -> None:
        lease = self.meta("control_lease")
        if lease is None:
            raise LeaseValidationError("active commissioning lease is required")
        if not isinstance(lease_token, str) or not isinstance(owner, str):
            raise LeaseValidationError("active lease token and owner are required")
        if not hmac.compare_digest(str(lease.get("token_digest", "")), hashlib.sha256(lease_token.encode()).hexdigest()):
            raise LeaseValidationError("lease token does not own the hardware command")
        if owner != lease.get("owner") or generation != lease.get("generation"):
            raise LeaseValidationError("lease owner or controller generation is stale")
        try:
            if datetime.fromisoformat(str(lease["expires_at"]).replace("Z", "+00:00")) <= datetime.now(UTC):
                raise LeaseValidationError("hardware lease has expired")
        except (KeyError, ValueError, TypeError) as error:
            raise LeaseValidationError("hardware lease expiry is invalid") from error

    def recovery_manifest(self, *, include_records: bool = True) -> Json:
        """Produce a self-contained, edge-authoritative recovery snapshot.

        The compact form used by normal heartbeat sync deliberately omits the
        append-only histories.  A full manifest is only sent after an explicit
        recovery request, so a long-running controller does not turn routine
        synchronization into an ever-growing payload.
        """
        identity, binding = self.identity(), self.binding()
        bundle_rows = self._connection.execute("SELECT payload FROM bundles ORDER BY id")
        bundles = [_decode(row["payload"]) for row in bundle_rows]
        runs = self.list_runs()
        patches = [_decode(r["payload"]) for r in self._connection.execute("SELECT payload FROM patches ORDER BY run_id, sequence")] if include_records else []
        events = [_decode(r["payload"]) for r in self._connection.execute("SELECT payload FROM events ORDER BY run_id, sequence")] if include_records else []
        run_action_executions = [self.run_action(row["command_id"]) for row in self._connection.execute(
            "SELECT command_id FROM run_action_executions ORDER BY created_at")] if include_records else []
        revisions = [self.revision(run["id"]) for run in runs]
        ranges = []
        for row in self._connection.execute("SELECT stream_id, MIN(sequence) lo, MAX(sequence) hi FROM telemetry GROUP BY stream_id"):
            records = self.telemetry_after(row["stream_id"], row["lo"] - 1)
            ranges.append({"controller_id": identity["id"], "stream_id": row["stream_id"], "start_sequence": row["lo"], "end_sequence": row["hi"], "digest": canonical_digest(records), "captured_at": _now()})
        completed_unsynchronized = []
        for run in runs:
            if run["state"] not in {"stopped", "completed", "failed"}:
                continue
            local_high = max((event["sequence"] for event in self.events_after(run["id"])), default=0)
            if int(self.cursor(f"central:event:{run['id']}")) < local_high:
                completed_unsynchronized.append(run)
        controller = {key: value for key, value in identity.items() if key != "credential"}
        if binding:
            controller["binding"] = {key: value for key, value in binding.items() if key != "credential"}
        return {"id": str(uuid.uuid4()), "controller_id": identity["id"],
                "controller_generation": binding["generation"] if binding else 0, "generated_at": _now(),
                "controller": controller, "instrument_inventory": self.list_instruments(),
                "active_runs": [r for r in runs if r["state"] in {"running", "paused", "stopping"}],
                "runs": runs, "bundles": bundles, "run_patches": patches, "run_events": events,
                "run_action_executions": run_action_executions,
                "run_revisions": revisions, "telemetry_ranges": ranges,
                "completed_unsynchronized_runs": completed_unsynchronized,
                "source_metadata": [s for b in bundles for s in b.get("source_metadata", [])],
                "runtime": {"controller_version": os.environ.get("EVOLVER_CONTROLLER_VERSION", "unknown"),
                            "python": os.sys.version.split()[0]}}
