from __future__ import annotations

import importlib
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient


@pytest.fixture()
def ui_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SECUREPROMPT_AUDIT_PATH", str(tmp_path / "audit.log"))
    import api.main as api_main

    importlib.reload(api_main)
    client = TestClient(api_main.app)

    yield client

    monkeypatch.delenv("SECUREPROMPT_AUDIT_PATH", raising=False)
    importlib.reload(api_main)


def test_dashboard_get(ui_client: TestClient) -> None:
    response = ui_client.get("/")
    assert response.status_code == 200
    assert "Sanitized Output" in response.text


def test_scrub_text_flow(ui_client: TestClient) -> None:
    response = ui_client.post("/ui/scrub", data={"clearance": "C3", "text": "Email a@b.com"})
    assert response.status_code == 200
    assert "Sanitized Output" in response.text


def test_upload_with_unsupported_extension(ui_client: TestClient) -> None:
    response = ui_client.post(
        "/ui/scrub",
        data={"clearance": "C3"},
        files={"upload": ("test.doc", b"hello", "application/msword")},
    )
    assert response.status_code == 200
    assert "Unsupported file type" in response.text
