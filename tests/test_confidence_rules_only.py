from __future__ import annotations

from secureprompt.scrub.pipeline import scrub_text


def test_confidence_for_rule_only_entities() -> None:
    text = "Email alice@example.com and card 4111 1111 1111 1111"
    result = scrub_text(text, c_level="C3")
    entities = result["entities"]
    email = next(e for e in entities if e["label"] == "EMAIL")
    pan = next(e for e in entities if e["label"] == "PAN")

    assert email["confidence"] == 0.98
    assert "rule" in email["explanation"].lower()
    assert pan["confidence"] == 0.99
    assert "rule" in pan["explanation"].lower()
