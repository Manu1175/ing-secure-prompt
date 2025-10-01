#!/usr/bin/env bash
set -euo pipefail

mkdir -p secureprompt/ml tests/ml

cat > secureprompt/ml/fusion.py <<'PY'
from typing import Any, Tuple

def _span_tuple(obj: Any) -> Tuple[int, int] | None:
    if obj is None:
        return None
    if isinstance(obj, dict):
        if "start" in obj and "end" in obj:
            return int(obj["start"]), int(obj["end"])
        if isinstance(obj.get("span"), dict) and "start" in obj["span"]:
            s = obj["span"]
            return int(s["start"]), int(s["end"])
    s = getattr(obj, "span", None)
    if s is not None and hasattr(s, "start") and hasattr(s, "end"):
        return int(getattr(s, "start")), int(getattr(s, "end"))
    return None

def overlaps(a: Any, b: Any) -> bool:
    sa = _span_tuple(a); sb = _span_tuple(b)
    if not sa or not sb:
        return False
    a0, a1 = sa; b0, b1 = sb
    return not (a1 <= b0 or b1 <= a0)

def fuse(rule_conf: float, ml_score: float, mode: str | None) -> float:
    try:
        rc = float(rule_conf); ms = float(ml_score)
    except Exception:
        return rule_conf
    m = (mode or "max").strip()
    if m == "avg":
        return (rc + ms) / 2.0
    if m.startswith("weighted:"):
        try:
            w = float(m.split(":", 1)[1])
        except Exception:
            w = 0.7
        if w < 0: w = 0.0
        if w > 1: w = 1.0
        return w * rc + (1 - w) * ms
    return rc if rc >= ms else ms
PY

cat > secureprompt/ml/wire.py <<'PY'
import os
from typing import Any, Dict, List
from . import ner, fusion

def _span_from_finding(f: Dict[str, Any]) -> Dict[str, int] | None:
    if "start" in f and "end" in f:
        return {"start": int(f["start"]), "end": int(f["end"])}
    s = f.get("span")
    if isinstance(s, dict) and "start" in s and "end" in s:
        return {"start": int(s["start"]), "end": int(s["end"])}
    return None

def apply_confidence_fusion(text: str, findings: List[Dict[str, Any]]):
    """No-op unless NER is enabled. Adds optional confidence_ml and confidence_fused."""
    if not ner.is_enabled():
        return findings
    ml = ner.predict(text)
    entities = getattr(ml, "entities", []) or []
    if not entities:
        return findings
    mode = os.getenv("SP_CONF_FUSION", "max")
    for f in findings:
        span = _span_from_finding(f)
        if not span:
            continue
        rc = f.get("confidence", f.get("confidence_rule"))
        try:
            rc = float(rc) if rc is not None else None
        except Exception:
            rc = None
        if rc is None:
            continue
        best = 0.0
        for e in entities:
            if fusion.overlaps({"span": span}, e):
                try:
                    best = max(best, float(getattr(e, "score", 0.0)))
                except Exception:
                    pass
        if best > 0:
            f["confidence_ml"] = best
            f["confidence_fused"] = fusion.fuse(rc, best, mode)
    return findings
PY

cat > tests/ml/test_fusion_disabled.py <<'PY'
def test_fusion_disabled_noop(monkeypatch):
    monkeypatch.delenv("SP_ENABLE_NER", raising=False)
    from secureprompt.ml.wire import apply_confidence_fusion
    text = "Email a@b.com"
    findings = [{"label": "EMAIL", "start": 6, "end": 12, "confidence": 0.6}]
    out = apply_confidence_fusion(text, [dict(f) for f in findings])
    assert out[0].get("confidence_ml") is None
    assert out[0].get("confidence_fused") is None
PY

cat > tests/ml/test_fusion_stubbed.py <<'PY'
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
PY

git add secureprompt/ml/fusion.py secureprompt/ml/wire.py tests/ml/test_fusion_disabled.py tests/ml/test_fusion_stubbed.py
git commit -m "feat(K2): optional ML confidence fusion (backward compatible)" || echo "Nothing to commit."
echo "K2 Phase 2 OK"
