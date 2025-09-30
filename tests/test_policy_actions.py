from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def _write_policy(dir_path: Path, action: str) -> None:
    content = (
        "- id: EMAIL_override\n"
        "  label: EMAIL\n"
        "  pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'\n"
        "  validator: none\n"
        f"  action: {action}\n"
        "  explanation: email address\n"
        "  confidence: 0.9\n"
    )
    for tier in ("c2", "c3", "c4"):
        (dir_path / f"{tier}.yml").write_text(content, encoding="utf-8")


def test_policy_action_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    _write_policy(policy_dir, "mask")

    monkeypatch.setenv("SECUREPROMPT_POLICY_DIR", str(policy_dir))

    import secureprompt.entities.detectors as detectors
    importlib.reload(detectors)
    import secureprompt.scrub.pipeline as pipeline
    importlib.reload(pipeline)

    masked = pipeline.scrub_text("Email a@b.com", c_level="C3")
    mask_entity = masked["entities"][0]
    assert mask_entity["action"] == "mask"
    assert mask_entity["mask_preview"].startswith("***")

    _write_policy(policy_dir, "redact")
    importlib.reload(detectors)
    importlib.reload(pipeline)

    redacted = pipeline.scrub_text("Email a@b.com", c_level="C3")
    assert "C3::EMAIL::" in redacted["scrubbed"]

    monkeypatch.delenv("SECUREPROMPT_POLICY_DIR", raising=False)
    importlib.reload(detectors)
    importlib.reload(pipeline)
