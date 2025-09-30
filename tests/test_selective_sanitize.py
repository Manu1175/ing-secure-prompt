from __future__ import annotations

from secureprompt.ui.selective import selective_sanitize


def test_selective_sanitize_masks_above_clearance() -> None:
    text = "AA1234BB"
    entities = [{"span": [2, 6], "c_level": "C3"}]

    assert selective_sanitize(text, entities, "C1") == "AA[REDACTED]BB"
    assert selective_sanitize(text, entities, "C3") == text
    assert selective_sanitize(text, entities, "C4") == text
