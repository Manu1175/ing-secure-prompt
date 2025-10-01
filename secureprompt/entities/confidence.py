"""Rule-based confidence utilities for the scrub pipeline."""

from __future__ import annotations

from typing import Dict, List

BASE_RULE_CONF: Dict[str, float] = {
    "EMAIL": 0.98,
    "IBAN": 0.99,
    "PAN": 0.99,
    "PHONE": 0.98,
    "NAME": 0.90,
    "ADDRESS": 0.90,
}


def add_confidence(rule_hits: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Annotate rule detection hits with confidence and explanation metadata."""

    for hit in rule_hits:
        label = str(hit.get("label") or "").upper()
        rule_conf = BASE_RULE_CONF.get(label, 0.90)
        sources = hit.setdefault("confidence_sources", {})  # type: ignore[assignment]
        if isinstance(sources, dict):
            sources["rule"] = rule_conf
        hit["confidence"] = rule_conf
        hit["explanation"] = f"rule {label or '?'} (base {rule_conf:.2f})"
    return rule_hits


__all__ = ["BASE_RULE_CONF", "add_confidence"]

