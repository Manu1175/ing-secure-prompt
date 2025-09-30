from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SECUREPROMPT_AUDIT_PATH", str(tmp_path / "audit.log"))
    import api.main as api_main

    importlib.reload(api_main)
    client = TestClient(api_main.app)

    yield client

    monkeypatch.delenv("SECUREPROMPT_AUDIT_PATH", raising=False)
    importlib.reload(api_main)


def test_scrub_endpoint_logs(api_client: TestClient, tmp_path: Path) -> None:
    payload = {"text": "Email a@b.com", "c_level": "C3"}
    response = api_client.post("/scrub", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "scrubbed" in data

    audit_log = tmp_path / "audit.log"
    assert audit_log.exists()
    assert "scrub" in audit_log.read_text(encoding="utf-8")


def test_descrub_role_gate(api_client: TestClient, tmp_path: Path) -> None:
    ok_resp = api_client.post(
        "/descrub",
        json={"ids": ["C3::EMAIL::abc"], "justification": "demo", "role": "admin"},
    )
    assert ok_resp.status_code == 200
    assert ok_resp.json()["status"] == "approved"

    fail_resp = api_client.post(
        "/descrub",
        json={"ids": ["C3::EMAIL::abc"], "justification": "demo", "role": "viewer"},
    )
    assert fail_resp.status_code == 422

    audit_log = tmp_path / "audit.log"
    content = audit_log.read_text(encoding="utf-8")
    assert "approved" in content
    assert "denied" in content
