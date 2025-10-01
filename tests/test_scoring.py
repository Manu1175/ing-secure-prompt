from __future__ import annotations

import importlib
import os
from pathlib import Path

import yaml

from secureprompt.ui import scoring
import pytest


def test_expected_filtering(tmp_path: Path, monkeypatch) -> None:
    placeholder_file = tmp_path / "placeholders.yml"
    yaml.safe_dump([
        {"label": "EMAIL", "c_level": "C3", "templates": ["<EMAIL>"]},
        {"label": "PAN", "c_level": "C4", "templates": ["<PAN>"]},
    ], placeholder_file.open("w", encoding="utf-8"))

    monkeypatch.setenv("SECUREPROMPT_PLACEHOLDERS_PATH", str(placeholder_file))
    importlib.reload(scoring)
    scoring.reset_cache()

    baseline_data = {
        "by_file": {
            "example.xlsx": {
                "by_label": {"EMAIL": 3, "PAN": 2},
                "by_c_level": {"C3": 3, "C4": 2},
            }
        }
    }

    expected_c3 = scoring.expected_for_file(baseline_data, "example.xlsx", "C3")
    assert expected_c3["by_label"] == {"PAN": 2}
    expected_c1 = scoring.expected_for_file(baseline_data, "example.xlsx", "C1")
    assert expected_c1["by_label"] == {"EMAIL": 3, "PAN": 2}

    achieved = scoring.achieved_counts([
        {"label": "EMAIL", "c_level": "C3"},
        {"label": "PAN", "c_level": "C4"},
        {"label": "PAN", "c_level": "C4"},
    ])
    result = scoring.score(expected_c1, achieved)
    assert result["score"] == pytest.approx(66.67, rel=1e-3)
    assert result["diff"]["missing"].get("EMAIL") == 2
