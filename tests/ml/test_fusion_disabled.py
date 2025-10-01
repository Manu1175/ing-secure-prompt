def test_fusion_disabled_noop(monkeypatch):
    monkeypatch.delenv("SP_ENABLE_NER", raising=False)
    from secureprompt.ml.wire import apply_confidence_fusion
    text = "Email a@b.com"
    findings = [{"label": "EMAIL", "start": 6, "end": 12, "confidence": 0.6}]
    out = apply_confidence_fusion(text, [dict(f) for f in findings])
    assert out[0].get("confidence_ml") is None
    assert out[0].get("confidence_fused") is None
