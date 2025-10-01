"""Utilities to reconstruct text from encrypted scrub receipts."""

from __future__ import annotations

from typing import Dict, Iterable, Optional, Set

from .store import decrypt_text

_ORDER = {"C1": 1, "C2": 2, "C3": 3, "C4": 4}


def _rank(level: Optional[str]) -> int:
    if not level:
        return 4
    return _ORDER.get(level.upper(), 4)


def descrub_text(
    *,
    scrubbed_text: str,
    receipt: Dict,
    clearance: str,
    ids: Optional[Iterable[str]] = None,
) -> str:
    """Reconstruct text by selectively replacing placeholders using a receipt."""
    result = scrubbed_text
    ids_set: Optional[Set[str]] = set(ids) if ids else None
    clearance_rank = _rank(clearance)

    placeholder_map = receipt.get("placeholder_map") or {}

    for entity in receipt.get("entities", []):
        identifier = entity.get("identifier")
        if not identifier:
            continue
        if ids_set is not None and identifier not in ids_set:
            continue
        if _rank(entity.get("c_level")) > clearance_rank:
            continue

        token = placeholder_map.get(identifier, identifier)
        try:
            original = decrypt_text(entity["original_enc"])
        except Exception:
            continue
        result = result.replace(token, original, 1)

    return result


__all__ = ["descrub_text"]
