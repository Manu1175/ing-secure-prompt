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
