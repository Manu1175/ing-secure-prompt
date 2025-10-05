import os
import json
import importlib
from pathlib import Path

from fastapi.testclient import TestClient


def _reload_app_with_roles():
    os.environ["SECUREPROMPT_DESCRUB_ROLES"] = "admin,reviewer"
    from api import main

    importlib.reload(main)
    return main.app


def test_descrub_returns_original(tmp_path, monkeypatch):
    receipts_dir = Path("data/receipts")
    receipts_dir.mkdir(parents=True, exist_ok=True)

    op = "testop1234567890"
    receipt = {
        "endpoint": "/scrub",
        "ts": "2025-10-04T20:11:54Z",
        "original": "Hello SECRET world",
        "actor": "pytest",
    }
    (receipts_dir / f"{op}.json").write_text(json.dumps(receipt))

    app = _reload_app_with_roles()
    client = TestClient(app)

    response = client.get(f"/descrub/{op}", params={"role": "reviewer", "just": "test"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["operation_id"] == op
    assert body["original"] == "Hello SECRET world"


def test_descrub_forbidden_role(tmp_path):
    os.environ["SECUREPROMPT_DESCRUB_ROLES"] = ""
    from api import main

    importlib.reload(main)
    client = TestClient(main.app)

    response = client.get("/descrub/doesntmatter", params={"role": "someone"})
    assert response.status_code == 403
