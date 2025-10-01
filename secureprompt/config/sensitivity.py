from __future__ import annotations
import os, pathlib
from typing import Dict

_DEFAULTS: Dict[str, Dict[str, float]] = {
  "C1": {"NAME":0.85, "ADDRESS":0.90, "ORG_NAME":0.90},
  "C2": {"NAME":0.80, "ADDRESS":0.85, "ORG_NAME":0.85},
  "C3": {"NAME":0.75, "ADDRESS":0.80, "ORG_NAME":0.80},
  "C4": {"NAME":0.70, "ADDRESS":0.75, "ORG_NAME":0.75},
}

def get_clearance() -> str:
    c = os.getenv("SP_CLEARANCE", "C3").upper()
    return c if c in ("C1","C2","C3","C4") else "C3"

def _load_yaml() -> Dict[str, Dict[str, Dict[str,float]]]:
    p = pathlib.Path("config/sensitivity.yml")
    if not p.exists(): return {"clearance_thresholds": _DEFAULTS}
    try:
        import yaml  # type: ignore
    except Exception:
        return {"clearance_thresholds": _DEFAULTS}
    try:
        data = yaml.safe_load(p.read_text()) or {}
        return data
    except Exception:
        return {"clearance_thresholds": _DEFAULTS}

def load_thresholds() -> Dict[str, Dict[str, float]]:
    data = _load_yaml().get("clearance_thresholds") or {}
    out = {k: dict(v) for k,v in _DEFAULTS.items()}
    for k,v in data.items():
        if k in out and isinstance(v, dict):
            out[k].update({kk: float(vv) for kk,vv in v.items()})
    return out

def get_active_thresholds() -> Dict[str,float]:
    return load_thresholds()[get_clearance()]

def format_note(th: Dict[str,float]) -> str:
    n = th.get("NAME",0.0); a = th.get("ADDRESS",0.0); o = th.get("ORG_NAME",0.0)
    return f"NER thresholds — NAME {n:.2f}, ADDRESS {a:.2f}, ORG {o:.2f}"
