from __future__ import annotations

import importlib
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    import secureprompt.audit.log as audit_log

    monkeypatch.chdir(tmp_path)
    importlib.reload(audit_log)

    import api.main as api_main
    importlib.reload(api_main)

    client = TestClient(api_main.app)
    client.audit_log = audit_log

    yield client

    importlib.reload(audit_log)
    importlib.reload(api_main)


def test_scrub_endpoint_logs(api_client: TestClient, tmp_path: Path) -> None:
    payload = {"text": "Email a@b.com", "c_level": "C3"}
    response = api_client.post("/scrub", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "scrubbed" in data
    assert data["operation_id"]
    audit_entries = api_client.audit_log.tail(5)
    assert any(entry.get("event") == "scrub" for entry in audit_entries)
    jsonl_files = list((tmp_path / "data" / "audit").glob("audit-*.jsonl"))
    assert jsonl_files


def test_descrub_role_gate(api_client: TestClient) -> None:
    scrub_payload = {"text": "Email a@b.com", "c_level": "C3"}
    scrub_resp = api_client.post("/scrub", json=scrub_payload)
    data = scrub_resp.json()
    op_id = data["operation_id"]

    ok_resp = api_client.post(
        "/descrub",
        json={"role": "admin", "operation_id": op_id, "clearance": "C3"},
    )
    assert ok_resp.status_code == 200
    ok_data = ok_resp.json()
    assert "a@b.com" in ok_data["descrubbed"]

    fail_resp = api_client.post(
        "/descrub",
        json={"role": "viewer", "operation_id": op_id, "clearance": "C3"},
    )
    assert fail_resp.status_code == 422

    events = api_client.audit_log.tail(10)
    assert any(entry.get("event") == "descrub" and entry.get("status") != "denied" for entry in events)
    assert any(entry.get("event") == "descrub" and entry.get("status") == "denied" for entry in events)
