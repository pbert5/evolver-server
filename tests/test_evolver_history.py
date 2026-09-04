from __future__ import annotations

from contextlib import contextmanager

import pytest

import meta_webui_application_backend.evolver_history as history


class FakeCursor:
    def __init__(self) -> None:
        self.events: dict[tuple[object, ...], str] = {}
        self.telemetry: dict[tuple[object, ...], str] = {}
        self.rows: list[dict[str, object]] = []

    def __enter__(self): return self
    def __exit__(self, *args): return False

    def execute(self, sql: str, params=()) -> None:
        if sql.startswith("INSERT INTO evolver.controller_event_history"):
            key, digest = (tuple(params[:4]), params[-1])
            self.events.setdefault(key, digest)
            self.rows = [{"payload_digest": self.events[key]}]
        elif sql.startswith("INSERT INTO evolver.controller_telemetry_history"):
            key, digest = (tuple(params[:4]), params[-1])
            self.telemetry.setdefault(key, digest)
            self.rows = [{"payload_digest": self.telemetry[key]}]
        elif sql.startswith("SELECT payload_digest FROM evolver.controller_event_history"):
            self.rows = [{"payload_digest": self.events[tuple(params)]}]
        elif sql.startswith("SELECT payload_digest FROM evolver.controller_telemetry_history"):
            self.rows = [{"payload_digest": self.telemetry[tuple(params)]}]
        else:
            raise AssertionError(sql)

    def fetchone(self): return self.rows[0] if self.rows else None


class FakeConnection:
    def __init__(self, cursor: FakeCursor): self.cursor_value = cursor
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def cursor(self): return self.cursor_value


@contextmanager
def fake_connection():
    cursor = FakeCursor()
    yield FakeConnection(cursor)


def test_payload_digest_is_order_stable():
    assert history.payload_digest({"a": 1, "b": 2}) == history.payload_digest({"b": 2, "a": 1})


def test_history_validates_fencing_and_query_bounds(monkeypatch):
    monkeypatch.setattr(history, "connection", fake_connection)
    repository = history.NormalizedHistoryRepository()
    with pytest.raises(history.HistoryError, match="positive"):
        repository.append_events([{"controller_id": "c", "controller_generation": 0, "run_id": "r", "sequence": 1, "event_type": "started"}])
    with pytest.raises(history.HistoryError, match="between"):
        repository.events(controller_id="c", limit=history.MAX_HISTORY_QUERY_LIMIT + 1)


def test_duplicate_fact_is_idempotent_and_conflicting_fact_is_rejected(monkeypatch):
    cursor = FakeCursor()

    @contextmanager
    def persistent_connection():
        yield FakeConnection(cursor)

    monkeypatch.setattr(history, "connection", persistent_connection)
    repository = history.NormalizedHistoryRepository()
    event = {"controller_id": "c", "controller_generation": 2, "run_id": "r", "sequence": 1, "event_type": "started", "payload": {"state": "running"}}
    repository.append_events([event])
    repository.append_events([event])
    # A new repository instance represents a process restart; identity is
    # still deduplicated by the durable store rather than process memory.
    history.NormalizedHistoryRepository().append_events([event])
    with pytest.raises(history.HistoryConflict, match="conflicts"):
        repository.append_events([{**event, "payload": {"state": "paused"}}])
    assert len(cursor.events) == 1


def test_telemetry_identity_is_generation_fenced_and_idempotent(monkeypatch):
    cursor = FakeCursor()

    @contextmanager
    def persistent_connection():
        yield FakeConnection(cursor)

    monkeypatch.setattr(history, "connection", persistent_connection)
    repository = history.NormalizedHistoryRepository()
    record = {"controller_id": "c", "controller_generation": 3, "stream_id": "instrument:i", "sequence": 4, "value": 1.5, "metric": "od"}
    repository.append_telemetry([record])
    repository.append_telemetry([record])
    with pytest.raises(history.HistoryConflict):
        repository.append_telemetry([{**record, "value": 2.0}])
    assert len(cursor.telemetry) == 1
