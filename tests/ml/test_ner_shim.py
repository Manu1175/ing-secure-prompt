import importlib

def test_disabled_predict_returns_empty(monkeypatch):
    # Ensure disabled regardless of whether transformers is installed
    monkeypatch.delenv("SP_ENABLE_NER", raising=False)
    import secureprompt.ml.ner as ner
    importlib.reload(ner)  # reset caches
    res = ner.predict("abc")
    assert hasattr(res, "entities")
    assert res.entities == []
    assert ner.is_enabled() is False
