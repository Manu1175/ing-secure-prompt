"""Mining utilities to infer placeholder usage within prompt spreadsheets."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import pandas as pd
from difflib import SequenceMatcher

PLACEHOLDER_RE = re.compile(r"^<[^>]+>$")
LABEL_PRIORITY = [
    "PAN",
    "IBAN",
    "PHONE",
    "EMAIL",
    "PASSWORD",
    "PIN",
    "CCV",
    "EXPIRY",
    "EXPIRY_DATE",
    "ADDRESS",
    "NAME",
    "NATIONAL_ID",
]

LABEL_C_LEVEL = {
    "EMAIL": "C3",
    "PHONE": "C3",
    "NAME": "C3",
    "ADDRESS": "C3",
    "PAN": "C4",
    "CCV": "C4",
    "EXPIRY_DATE": "C4",
    "IBAN": "C3",
    "PIN": "C4",
    "PASSWORD": "C4",
    "NATIONAL_ID": "C3",
}


def _normalise_placeholder(placeholder: str) -> str:
    token = placeholder.strip("<>").upper()
    for label in LABEL_PRIORITY:
        if label in token:
            return label
    if "EXPIRY" in token:
        return "EXPIRY_DATE"
    if "CARD" in token:
        return "PAN"
    if "EMAIL" in token or "MAIL" in token:
        return "EMAIL"
    if "PHONE" in token or "TEL" in token:
        return "PHONE"
    if "NAME" in token:
        return "NAME"
    if "ADDRESS" in token:
        return "ADDRESS"
    return token or "UNKNOWN"


def _extract_pairs(original: str, sanitized: str) -> Iterable[tuple[str, str]]:
    orig_tokens = original.split()
    san_tokens = sanitized.split()
    matcher = SequenceMatcher(None, san_tokens, orig_tokens)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        segment = san_tokens[i1:i2]
        if not segment:
            continue
        for idx, token in enumerate(segment):
            if PLACEHOLDER_RE.match(token):
                original_tokens = orig_tokens[j1:j2]
                if not original_tokens and j1 < len(orig_tokens):
                    original_tokens = [orig_tokens[j1]]
                original_chunk = " ".join(original_tokens)
                yield token, original_chunk


def mine_prompts(folder: str) -> Dict[str, Dict[str, Any]]:
    folder_path = Path(folder)
    aggregates: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"templates": set(), "examples": set()})

    for xlsx in folder_path.glob("*.xlsx"):
        try:
            df = pd.read_excel(xlsx, engine="openpyxl")
        except Exception:  # pragma: no cover
            continue

        if "Original Prompt" not in df.columns or "Sanitized Prompt" not in df.columns:
            continue

        for _, row in df.iterrows():
            original = str(row.get("Original Prompt", "") or "").strip()
            sanitized = str(row.get("Sanitized Prompt", "") or "").strip()
            if not original or not sanitized:
                continue
            for placeholder, example in _extract_pairs(original, sanitized):
                label = _normalise_placeholder(placeholder)
                entry = aggregates[label]
                entry["templates"].add(placeholder)
                if example:
                    entry["examples"].add(example)

    result: Dict[str, Dict[str, Any]] = {}
    for label, data in aggregates.items():
        c_level = LABEL_C_LEVEL.get(label, "C3")  # TODO: infer from manifests
        result[label] = {
            "c_level": c_level,
            "templates": sorted(data["templates"]),
            "examples": sorted(data["examples"]),
        }
    return result


def write_placeholders_yaml(data: Dict[str, Dict[str, Any]], path: str = "policy/placeholders.yml") -> Path:
    import yaml

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=True)
    return target


__all__ = ["mine_prompts", "write_placeholders_yaml"]
