from copy import deepcopy
from http import HTTPStatus
from pathlib import Path
import json

from meta_webui_application_backend.evolver_control import contract, service


def test_full_discovery_preserves_contract_metadata_and_filters_missing_adapters(monkeypatch, tmp_path):
    action = {"id": "demo.read", "title": "Read", "parameters": {"id": {"type": "string", "required": True}},
              "permissions": ["read"], "status": "implemented", "evidence": {"kind": "software", "source": "test", "tests": ["tests/test.py"]},
              "safety": {"risk": "low", "confirmation": "none", "reversible": True}}
    unavailable = {**deepcopy(action), "id": "demo.missing"}
    document = {"version": "1.0.0", "deployment_index": [action["id"], unavailable["id"]], "actions": [action, unavailable],
                "api": {action["id"]: {"method": "GET", "path": "/api/demo/{id}"}, unavailable["id"]: {"method": "POST", "path": "/api/demo"}}}
    path = tmp_path / "actions.json"
    path.write_text(json.dumps(document))
    monkeypatch.setattr(contract, "catalog_path", lambda: path)
    monkeypatch.setattr(contract, "ACTION_ADAPTERS", {"demo.read": object()})
    payload = contract.workbench_manifest()
    assert payload["format"] == "meta-api-catalog/1"
    assert payload["unavailable"] == ["demo.missing"]
    assert payload["catalogs"][0]["catalog"]["actions"] == [action]
    assert payload["catalogs"][0]["catalog"]["api"] == {action["id"]: document["api"][action["id"]]}


def test_discovery_handler_is_read_only_and_keeps_legacy_endpoint(monkeypatch):
    called = []
    monkeypatch.setattr(contract, "workbench_manifest", lambda: {"format": "meta-api-catalog/1"})
    monkeypatch.setattr(contract, "manifest", lambda: {"actions": []})
    handler = object.__new__(service.EvolverControlHandler)
    handler._send = lambda status, payload: called.append((status, payload))
    handler.path = "/api/meta/actions"
    handler._handle("GET")
    handler.path = "/api/actions"
    handler._handle("GET")
    assert called == [(HTTPStatus.OK, {"format": "meta-api-catalog/1"}), (HTTPStatus.OK, {"actions": []})]


def test_discovery_failure_does_not_leak_paths(monkeypatch):
    def fail():
        raise OSError("/private/secret-path")
    monkeypatch.setattr(contract, "workbench_manifest", fail)
    handler = object.__new__(service.EvolverControlHandler)
    called = []
    handler._send = lambda status, payload: called.append((status, payload))
    handler.path = "/api/meta/actions"
    handler._handle("GET")
    assert called[0][0] == HTTPStatus.SERVICE_UNAVAILABLE
    assert "secret-path" not in json.dumps(called)
