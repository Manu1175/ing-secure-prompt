"""Scrubbing pipeline transforming raw text via policy-driven detectors."""

from __future__ import annotations

import hashlib
import os
from typing import Dict, Any, List

from ..entities.detectors import detect


def _salt() -> str:
    """Return the configured hashing salt with a sensible default."""

    return os.environ.get("SECUREPROMPT_SALT", "change-me")


def _identifier(label: str, value: str, c_level: str) -> str:
    """Derive the deterministic identifier for a sensitive value."""

    h = hashlib.sha256((_salt() + value).encode("utf-8")).hexdigest()[:10]
    return f"{c_level}::{label}::{h}"


def _mask_value(value: str) -> str:
    """Mask a value using fixed-width asterisks preserving length."""

    return "*" * max(len(value), 3)


def scrub_text(text: str, c_level: str = "C3") -> Dict[str, Any]:
    """Scrub sensitive entities from ``text`` according to active policies."""

    hits = detect(text)
    out = text
    entities: List[Dict[str, Any]] = []

    for hit in sorted(hits, key=lambda x: x["start"], reverse=True):
        identifier = _identifier(hit["label"], hit["value"], c_level)
        action = hit.get("action", "redact")
        mask_preview = _mask_value(hit["value"]) if action == "mask" else None

        out = out[: hit["start"]] + identifier + out[hit["end"] :]

        entity = {
            "label": hit["label"],
            "span": [hit["start"], hit["end"]],
            "detector": hit["rule_id"],
            "confidence": hit["confidence"],
            "c_level": c_level,
            "identifier": identifier,
            "action": action,
        }
        if mask_preview is not None:
            entity["mask_preview"] = mask_preview

        entities.append(entity)

    return {
        "original_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "scrubbed": out,
        "entities": list(reversed(entities)),
    }


__all__ = ["scrub_text"]
