from __future__ import annotations

from pathlib import Path

import pytest

from meta_webui_application_backend.central_store import (
    CentralStoreConfigurationError,
    PostgresCentralControllerStore,
    configured_store,
)
from evolver_server.persistence.legacy_import import import_legacy_state


def test_runtime_store_requires_postgres(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("META_WEBUI_INTERFACE_DATABASE_URL", raising=False)

    with pytest.raises(CentralStoreConfigurationError, match="DATABASE_URL"):
        configured_store(json_path=tmp_path / "ignored.json", explicit_state_root=False)


def test_runtime_store_never_uses_json_bootstrap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://disposable/example")

    store = configured_store(json_path=tmp_path / "legacy.json", explicit_state_root=False)

    assert isinstance(store, PostgresCentralControllerStore)
    assert store.bootstrap_path is None


def test_postgres_store_has_no_document_or_broad_mirror_authority() -> None:
    source = Path(PostgresCentralControllerStore.__module__.replace(".", "/") + ".py")
    source = Path(__file__).parents[1] / "src" / "meta_webui_application_backend" / "central_store.py"
    text = source.read_text(encoding="utf-8")

    assert "evolver.central_state" not in text
    assert "def _mirror" not in text
    assert "DELETE FROM evolver" not in text


def test_json_store_is_explicit_legacy_only() -> None:
    source = Path(__file__).parents[1] / "src" / "meta_webui_application_backend" / "central_store.py"
    text = source.read_text(encoding="utf-8")

    assert "JsonBootstrapCentralControllerStore" in text
    assert "explicit_state_root" in text


def test_legacy_import_dry_run_is_read_only_and_digest_backed(tmp_path: Path) -> None:
    source = tmp_path / "legacy.json"
    source.write_text('{"controllers":{"edge-a":{}}}', encoding="utf-8")

    summary = import_legacy_state(source, url="postgresql://unused/example", dry_run=True)

    assert summary["dry_run"] is True
    assert len(summary["source_digest"]) == 64
    assert source.read_text(encoding="utf-8") == '{"controllers":{"edge-a":{}}}'
