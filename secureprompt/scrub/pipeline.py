import os, hashlib
from typing import Dict, Any
from ..entities.detectors import detect

def _salt() -> str:
    return os.environ.get("SECUREPROMPT_SALT", "change-me")

def _identifier(label: str, value: str, c_level: str) -> str:
    h = hashlib.sha256((_salt()+value).encode("utf-8")).hexdigest()[:10]
    return f"{c_level}::{label}::{h}"

def scrub_text(text: str, c_level: str="C3") -> Dict[str, Any]:
    hits = detect(text)
    out = text
    explanations = []
    # replace from end to start to keep indices valid
    for h in sorted(hits, key=lambda x: x["start"], reverse=True):
        ident = _identifier(h["label"], h["value"], c_level)
        out = out[:h["start"]] + ident + out[h["end"]:]
        explanations.append({
            "label": h["label"],
            "span": [h["start"], h["end"]],
            "detector": h["rule_id"],
            "confidence": h["confidence"],
            "c_level": c_level,
            "identifier": ident
        })
    return {"original_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(), "scrubbed": out, "entities": explanations}
