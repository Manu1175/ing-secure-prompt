from __future__ import annotations

from secureprompt.receipts.store import read_receipt
from secureprompt.scrub.pipeline import scrub_text


def test_receipt_contains_confidence_metadata(tmp_path) -> None:
    text = "Contact alice@example.com"
    result = scrub_text(text, c_level="C3")
    receipt = read_receipt(result["operation_id"])

    entities = receipt.get("entities", [])
    assert entities
    entity = entities[0]
    assert "confidence" in entity
    assert "confidence_sources" in entity
    assert entity["confidence_sources"].get("rule") == entity["confidence"]
    assert "explanation" in entity
