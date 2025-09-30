import json
from pathlib import Path

import pytest

from secureprompt.eval.metrics import evaluate_golden


@pytest.fixture()
def stub_scrubber():
    outputs = {
        "Email: alice@example.com": {
            "text": "Email: [EMAIL]",
            "entities": [{"label": "EMAIL"}],
        },
        "Phone 555-0101": {
            "text": "Phone 555-0101",
            "entities": [],
        },
        "Lives at 123 Main": {
            "text": "Lives at [ADDRESS]",
            "entities": [{"label": "ADDRESS"}],
        },
    }

    def _scrub(text: str):
        try:
            return outputs[text]
        except KeyError as exc:
            raise AssertionError(f"Unexpected text: {text}") from exc

    return _scrub


def _write_jsonl(path: Path, records):
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def test_evaluate_golden(tmp_path: Path, stub_scrubber) -> None:
    data_dir = tmp_path / "golden"
    data_dir.mkdir()

    records = [
        {
            "label": "email",
            "raw_text": "Email: alice@example.com",
            "entities": [{"value": "alice@example.com"}],
            "expected_scrub": "Email: [EMAIL]",
        },
        {
            "label": "email",
            "raw_text": "Phone 555-0101",
            "entities": [{"value": "555-0101"}],
            "expected_scrub": "Phone [PHONE]",
        },
        {
            "label": "address",
            "raw_text": "Lives at 123 Main",
            "entities": [{"value": "123 Main"}],
        },
    ]

    _write_jsonl(data_dir / "sample.jsonl", records)

    report_path = tmp_path / "metrics.md"
    summary = evaluate_golden(data_dir=data_dir, report_path=report_path, scrubber=stub_scrubber)

    email_metrics = summary["by_label"]["email"]
    assert email_metrics["n"] == 2
    assert email_metrics["residual_hits"] == 1
    assert email_metrics["replaced"] == 1
    assert email_metrics["exact_matches"] == 1
    assert pytest.approx(email_metrics["recall"]) == pytest.approx(0.5)
    assert email_metrics["notes"] == ""

    address_metrics = summary["by_label"]["address"]
    assert address_metrics["n"] == 1
    assert address_metrics["residual_hits"] == 0
    assert address_metrics["replaced"] == 1
    assert address_metrics["exact_matches"] == 0
    assert address_metrics["notes"] == "1 missing expected"

    overall = summary["overall"]
    assert overall["n"] == 3
    assert overall["residual_hits"] == 1
    assert overall["replaced"] == 2
    assert overall["exact_matches"] == 1

    report = report_path.read_text(encoding="utf-8")
    assert "| label | n | residual_hits" in report
    assert "| overall" in report

