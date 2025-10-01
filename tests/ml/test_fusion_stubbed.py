from types import SimpleNamespace

def test_fusion_with_stubbed_ner(monkeypatch):
    import secureprompt.ml.ner as ner
    from secureprompt.ml import wire

    # Force "enabled" and stub predict to avoid transformers/model downloads
    monkeypatch.setenv("SP_ENABLE_NER", "1")
    monkeypatch.setenv("SP_CONF_FUSION", "max")
    monkeypatch.setattr(ner, "is_enabled", lambda: True)
    ent = SimpleNamespace(label="EMAIL", score=0.9, span=SimpleNamespace(start=6, end=12), text="a@b.com")
    monkeypatch.setattr(ner, "predict", lambda _text: SimpleNamespace(entities=[ent]))

    text = "Email a@b.com"
    findings = [{"label": "EMAIL", "start": 6, "end": 12, "confidence": 0.6}]
    out = wire.apply_confidence_fusion(text, findings)
    assert out[0]["confidence_ml"] == 0.9
    assert out[0]["confidence_fused"] == 0.9  # max(0.6, 0.9)
