from __future__ import annotations
import os, re, yaml
from typing import Iterable, Dict, List, Tuple

HERE = os.path.dirname(__file__)

# Defaults; can be overridden by config/prompt_lexicon.yml
DEFAULTS = {
    "AMOUNT": r"(?:(?:€|$|£)\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?|\b(?:EUR|USD|GBP)\s?\d+(?:[.,]\d{2})?)",
    "DATE": r"\b\d{1,2}[./-]\d{1,2}[./-]\d{2,4}\b",
    "YEAR": r"\b(19|20)\d{2}\b",
    "LINK": r"\bhttps?://[^\s)]+",
    "DOCUMENT_TYPE": r"\b(Annual\s+Report|Pillar\s*3\s*Disclosures?)\b",
}

def _load_rules() -> List[Tuple[str, re.Pattern]]:
    cfg_paths = [
        os.path.join("config","prompt_lexicon.yml"),
        os.path.join("config","prompt_lexicon.auto.yml"),
    ]
    rules: List[Tuple[str, re.Pattern]] = []
    for path in cfg_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            except yaml.YAMLError:
                continue
            for label, rx in (data.get("rules") or {}).items():
                rules.append((label.strip().upper(), re.compile(rx, re.IGNORECASE)))
            break
    if not rules:
        for label, rx in DEFAULTS.items():
            rules.append((label, re.compile(rx, re.IGNORECASE)))
    return rules

_RULES = _load_rules()

def to_tokens(text: str) -> str:
    out = text
    for label, rx in _RULES:
        out = rx.sub(f"<{label}>", out)
    return out

def iter_spans(text: str) -> List[Dict[str, int | str]]:
    """Return [{'label', 'start', 'end'}] spans from lexicon matches (no replacement)."""
    out: List[Dict[str, int | str]] = []
    for label, rx in _RULES:
        for m in rx.finditer(text):
            s, e = m.span()
            out.append({"label": label, "start": s, "end": e})
    return out
