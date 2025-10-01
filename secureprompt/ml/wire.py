import os
from typing import Any, Dict, List

from secureprompt.config.sensitivity import get_active_thresholds
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
    thr = get_active_thresholds()
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
    if os.getenv("SP_ALLOW_ML_ONLY") == "1":
        label_map = {
            "PERSON": "NAME",
            "PER": "NAME",
            "ORG": "ORG_NAME",
            "ORGANIZATION": "ORG_NAME",
            "LOC": "ADDRESS",
            "LOCATION": "ADDRESS",
            "GPE": "ADDRESS",
        }
        for e in entities:
            overlaps_existing = False
            for f in findings:
                span = _span_from_finding(f)
                if span and fusion.overlaps({"span": span}, e):
                    overlaps_existing = True
                    break
            if overlaps_existing:
                continue
            raw_label = str(getattr(e, "label", ""))
            label = raw_label.upper()
            if "-" in label:
                label = label.split("-", 1)[-1]
            mapped_label = label_map.get(label)
            if not mapped_label:
                continue
            try:
                score = float(getattr(e, "score", 0.0))
            except Exception:
                continue
            if score < float(thr.get(mapped_label, 0.80)):
                continue
            span = getattr(e, "span", None)
            start = int(getattr(span, "start", 0)) if span is not None else 0
            end = int(getattr(span, "end", 0)) if span is not None else 0
            findings.append({
                "label": mapped_label,
                "start": start,
                "end": end,
                "text": getattr(e, "text", ""),
                "source": "ml",
                "confidence_ml": score,
                "confidence_fused": score,
            })
    return findings
