from types import SimpleNamespace

import pytest

from secureprompt.ml.wire import apply_confidence_fusion
from secureprompt.config.sensitivity import get_active_thresholds, format_note

def _setup_ml(monkeypatch, score: float):
    monkeypatch.setenv("SP_ENABLE_NER", "1")
    monkeypatch.setenv("SP_ALLOW_ML_ONLY", "1")

    import secureprompt.ml.ner as ner

    entity = SimpleNamespace(
        label="PERSON",
        score=score,
        span=SimpleNamespace(start=6, end=12),
        text="X",
    )
    monkeypatch.setattr(ner, "is_enabled", lambda: True)
    monkeypatch.setattr(ner, "predict", lambda _text: SimpleNamespace(entities=[entity]))


def test_ml_only_respects_clearance(monkeypatch):
    _setup_ml(monkeypatch, score=0.78)

    monkeypatch.setenv("SP_CLEARANCE", "C1")
    findings_high = apply_confidence_fusion("abc def", [])
    assert findings_high == []

    monkeypatch.setenv("SP_CLEARANCE", "C3")
    findings_mid = apply_confidence_fusion("abc def", [])
    assert len(findings_mid) == 1
    finding = findings_mid[0]
    assert finding["label"] == "NAME"
    assert finding["confidence_ml"] == pytest.approx(0.78)


def test_format_note_reflects_active_threshold(monkeypatch):
    monkeypatch.setenv("SP_CLEARANCE", "C2")
    note = format_note(get_active_thresholds())
    assert "0.80" in note
