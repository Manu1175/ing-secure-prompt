#!/usr/bin/env bash
set -euo pipefail

mkdir -p secureprompt/ml tests/ml
[ -f secureprompt/ml/__init__.py ] || printf '' > secureprompt/ml/__init__.py

cat > secureprompt/ml/ner.py <<'PY'
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import List, Optional

_enabled_cache: Optional[bool] = None
_pipeline_cache = None
_transformers_unavailable = False

@dataclass
class Span:
    start: int
    end: int

@dataclass
class Entity:
    label: str
    score: float
    span: Span
    text: str

@dataclass
class NERResult:
    entities: List[Entity]

def _lazy_import_transformers():
    global _transformers_unavailable
    if _transformers_unavailable:
        return None
    try:
        # Import inside function to stay lazy
        from transformers import pipeline  # type: ignore
        return pipeline
    except Exception:
        _transformers_unavailable = True
        return None

def is_enabled() -> bool:
    """Enabled only if env flag is '1' AND transformers import succeeds."""
    global _enabled_cache
    if _enabled_cache is not None:
        return _enabled_cache
    if os.getenv("SP_ENABLE_NER") != "1":
        _enabled_cache = False
        return False
    pipe_ctor = _lazy_import_transformers()
    _enabled_cache = pipe_ctor is not None
    return _enabled_cache

def get_pipeline():
    """Lazy singleton pipeline; never raises; returns None on any failure."""
    global _pipeline_cache
    if not is_enabled():
        return None
    if _pipeline_cache is not None:
        return _pipeline_cache
    pipe_ctor = _lazy_import_transformers()
    if pipe_ctor is None:
        return None
    model_name = os.getenv("SP_NER_MODEL", "dslim/bert-base-NER")
    try:
        _pipeline_cache = pipe_ctor(
            "token-classification",
            model=model_name,
            aggregation_strategy="simple",
        )
    except Exception:
        _pipeline_cache = None
    return _pipeline_cache

def predict(text: str) -> NERResult:
    if not is_enabled():
        return NERResult(entities=[])
    pipe = get_pipeline()
    if pipe is None:
        return NERResult(entities=[])
    try:
        raw = pipe(text)
    except Exception:
        return NERResult(entities=[])
    entities: List[Entity] = []
    for r in (raw or []):
        start = int(r.get("start", 0))
        end = int(r.get("end", 0))
        if end < start:
            start, end = 0, 0
        label = str(r.get("entity_group") or r.get("entity") or "MISC")
        score = float(r.get("score", 0.0))
        snippet = r.get("word")
        if not snippet and 0 <= start <= len(text) and 0 <= end <= len(text):
            snippet = text[start:end]
        entities.append(Entity(label=label, score=score, span=Span(start, end), text=snippet or ""))
    return NERResult(entities=entities)
PY

cat > tests/ml/test_ner_shim.py <<'PY'
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
PY

git add secureprompt/ml/ner.py secureprompt/ml/__init__.py tests/ml/test_ner_shim.py
git commit -m "feat(K2): add optional NER shim (lazy, disabled by default)" || echo "Nothing to commit."
echo "K2 Phase 1 OK"
