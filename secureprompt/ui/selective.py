"""Selective sanitisation utilities used by the UI layer."""

from __future__ import annotations

from typing import Dict, List, Sequence, Tuple

_ORDER = {"C1": 1, "C2": 2, "C3": 3, "C4": 4}


def level_gt(a: str, b: str) -> bool:
    """Return ``True`` when level ``a`` is strictly more sensitive than ``b``."""

    return _ORDER.get((a or "").upper(), 4) > _ORDER.get((b or "").upper(), 1)


def selective_sanitize(original: str, entities: List[Dict], clearance: str) -> str:
    """Mask entities whose ``c_level`` exceeds the provided ``clearance``.

    The input ``entities`` list is expected to contain ``span`` entries describing
    the character offsets in the original text. When no suitable spans are found
    the original text is returned unchanged so callers can fall back to generic
    scrubbing output.
    """

    spans: List[Tuple[int, int, bool]] = []
    clearance = (clearance or "C1").upper()

    for entity in entities or []:
        span = entity.get("span")
        if not isinstance(span, Sequence) or len(span) != 2:
            continue
        try:
            start, end = int(span[0]), int(span[1])
        except Exception:  # pragma: no cover - defensive
            continue
        if start < 0 or end <= start:
            continue
        level = (entity.get("c_level") or "C4").upper()
        mask = level_gt(level, clearance)
        spans.append((start, end, mask))

    if not spans:
        return original

    spans.sort(key=lambda item: item[0])
    out: List[str] = []
    cursor = 0
    for start, end, mask in spans:
        if start < cursor:
            continue
        out.append(original[cursor:start])
        segment = "[REDACTED]" if mask else original[start:end]
        out.append(segment)
        cursor = end

    out.append(original[cursor:])
    return "".join(out)


__all__ = ["level_gt", "selective_sanitize"]

