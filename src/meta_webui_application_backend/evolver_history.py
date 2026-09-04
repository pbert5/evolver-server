"""Durable normalized history for controller-originated events and telemetry.

History is evidence, not intent.  Rows are identified by the controller's
generation and stream sequence; retries with the same content are harmless,
while reuse of an identity with different content is a conflict.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from meta_webui_application_backend.db import connection


MAX_HISTORY_QUERY_LIMIT = 500


class HistoryError(ValueError):
    """Invalid history input."""


class HistoryConflict(HistoryError):
    """A durable history identity was reused with different content."""


def payload_digest(payload: Mapping[str, Any]) -> str:
    if not isinstance(payload, Mapping):
        raise HistoryError("payload must be an object")
    encoded = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HistoryError(f"{field} is required")
    return value.strip()


def _identity(controller_id: Any, generation: Any, sequence: Any, *, stream: str) -> None:
    _text(controller_id, "controller_id")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation <= 0:
        raise HistoryError("controller_generation must be positive")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        raise HistoryError(f"{stream} sequence must be positive")


def _limit(limit: int) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_HISTORY_QUERY_LIMIT:
        raise HistoryError(f"limit must be between 1 and {MAX_HISTORY_QUERY_LIMIT}")
    return limit


class NormalizedHistoryRepository:
    """Small PostgreSQL data-access layer for append-only controller facts."""

    def append_events(self, records: Sequence[Mapping[str, Any]]) -> None:
        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            raise HistoryError("records must be a sequence")
        with connection() as conn, conn.cursor() as cur:
            for record in records:
                if not isinstance(record, Mapping):
                    raise HistoryError("event record must be an object")
                controller_id, generation, run_id, sequence = (record.get(key) for key in ("controller_id", "controller_generation", "run_id", "sequence"))
                _identity(controller_id, generation, sequence, stream="event")
                run_id = _text(run_id, "run_id")
                event_type = _text(record.get("event_type"), "event_type")
                payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else dict(record)
                digest = payload_digest(payload)
                cur.execute("""INSERT INTO evolver.controller_event_history
                    (controller_id, controller_generation, run_id, sequence, event_id, event_type,
                     occurred_at, payload, payload_digest)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                    ON CONFLICT (controller_id, controller_generation, run_id, sequence) DO NOTHING""",
                    (controller_id, generation, run_id, sequence, record.get("event_id"), event_type,
                     record.get("occurred_at"), json.dumps(dict(payload)), digest))
                cur.execute("""SELECT payload_digest FROM evolver.controller_event_history
                    WHERE controller_id=%s AND controller_generation=%s AND run_id=%s AND sequence=%s""",
                    (controller_id, generation, run_id, sequence))
                row = cur.fetchone()
                if not row or row["payload_digest"] != digest:
                    raise HistoryConflict("event sequence conflicts with durable central record")

    def append_telemetry(self, records: Sequence[Mapping[str, Any]]) -> None:
        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            raise HistoryError("records must be a sequence")
        with connection() as conn, conn.cursor() as cur:
            for record in records:
                if not isinstance(record, Mapping):
                    raise HistoryError("telemetry record must be an object")
                controller_id, generation, stream_id, sequence = (record.get(key) for key in ("controller_id", "controller_generation", "stream_id", "sequence"))
                _identity(controller_id, generation, sequence, stream="telemetry")
                stream_id = _text(stream_id, "stream_id")
                payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else dict(record)
                digest = payload_digest(payload)
                cur.execute("""INSERT INTO evolver.controller_telemetry_history
                    (controller_id, controller_generation, stream_id, sequence, instrument_id,
                     vial_position_id, captured_at, metric, value, unit, payload, payload_digest)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
                    ON CONFLICT (controller_id, controller_generation, stream_id, sequence) DO NOTHING""",
                    (controller_id, generation, stream_id, sequence, record.get("instrument_id"),
                     record.get("vial_position_id"), record.get("captured_at"), record.get("metric"),
                     record.get("value"), record.get("unit"), json.dumps(dict(payload)), digest))
                cur.execute("""SELECT payload_digest FROM evolver.controller_telemetry_history
                    WHERE controller_id=%s AND controller_generation=%s AND stream_id=%s AND sequence=%s""",
                    (controller_id, generation, stream_id, sequence))
                row = cur.fetchone()
                if not row or row["payload_digest"] != digest:
                    raise HistoryConflict("telemetry sequence conflicts with durable central record")

    def events(self, *, controller_id: str, run_id: str | None = None,
               generation: int | None = None, after_sequence: int = 0,
               limit: int = 100) -> list[dict[str, Any]]:
        return self._query("event", controller_id=controller_id, stream_id=run_id,
                           generation=generation, after_sequence=after_sequence, limit=limit)

    def telemetry(self, *, controller_id: str, stream_id: str | None = None,
                  generation: int | None = None, after_sequence: int = 0,
                  limit: int = 100) -> list[dict[str, Any]]:
        return self._query("telemetry", controller_id=controller_id, stream_id=stream_id,
                           generation=generation, after_sequence=after_sequence, limit=limit)

    def _query(self, kind: str, *, controller_id: str, stream_id: str | None,
               generation: int | None, after_sequence: int, limit: int) -> list[dict[str, Any]]:
        _text(controller_id, "controller_id")
        if generation is not None and (not isinstance(generation, int) or generation <= 0):
            raise HistoryError("generation must be positive")
        if not isinstance(after_sequence, int) or after_sequence < 0:
            raise HistoryError("after_sequence must be non-negative")
        limit = _limit(limit)
        table, key = (("controller_event_history", "run_id") if kind == "event" else ("controller_telemetry_history", "stream_id"))
        columns = "controller_id, controller_generation, run_id, sequence, event_id, event_type, occurred_at, payload" if kind == "event" else "controller_id, controller_generation, stream_id, sequence, instrument_id, vial_position_id, captured_at, metric, value, unit, payload"
        clauses = ["controller_id=%s", f"{key}=%s" if stream_id is not None else "TRUE", "sequence>%s"]
        params: list[Any] = [controller_id]
        if stream_id is not None:
            params.append(stream_id)
        params.append(after_sequence)
        if generation is not None:
            clauses.append("controller_generation=%s")
            params.append(generation)
        params.append(limit)
        with connection() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {columns} FROM evolver.{table} WHERE {' AND '.join(clauses)} ORDER BY sequence LIMIT %s", tuple(params))
            return [dict(row) for row in cur.fetchall()]
