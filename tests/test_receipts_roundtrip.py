from __future__ import annotations

from secureprompt.scrub.pipeline import scrub_text
from secureprompt.receipts.store import read_receipt
from secureprompt.receipts.descrub import descrub_text


def test_receipts_roundtrip() -> None:
    text = "Contact a@b.com. RRN 93.07.15-123-66."
    result = scrub_text(text=text, c_level="C3")

    assert "a@b.com" not in result["scrubbed"]
    assert "93.07.15-123-66" not in result["scrubbed"]

    operation_id = result["operation_id"]
    assert operation_id
    assert result["receipt_path"]

    receipt = read_receipt(operation_id)

    out_c3 = descrub_text(scrubbed_text=result["scrubbed"], receipt=receipt, clearance="C3")
    assert "a@b.com" in out_c3
    assert "93.07.15-123-66" not in out_c3

    out_c4 = descrub_text(scrubbed_text=result["scrubbed"], receipt=receipt, clearance="C4")
    assert "a@b.com" in out_c4
    assert "93.07.15-123-66" in out_c4
