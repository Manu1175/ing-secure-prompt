"""Scrubbing pipeline transforming raw text via policy-driven detectors."""

from __future__ import annotations

import hashlib
import os
from uuid import uuid4
from typing import Dict, Any, List

from ..entities.detectors import detect
from ..entities.confidence import add_confidence

CLEARANCE_ORDER = {"C1": 1, "C2": 2, "C3": 3, "C4": 4}
from ..receipts.store import write_receipt
from ..audit.vault import Vault

ENTITY_DEFAULT_C_LEVEL = {
    "EMAIL": "C3",
    "PHONE": "C4",
    "NAME": "C3",
    "ADDRESS": "C3",
    "PAN": "C4",
    "CCV": "C4",
    "EXPIRY_DATE": "C4",
    "IBAN": "C3",
    "PIN": "C4",
    "PASSWORD": "C4",
    "NATIONAL_ID": "C4",
}


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

    hits = add_confidence(detect(text))
    out = text
    entities: List[Dict[str, Any]] = []
    receipt_entities: List[Dict[str, Any]] = []

    value_map: Dict[str, str] = {}

    for hit in sorted(hits, key=lambda x: x["start"], reverse=True):
        entity_level = ENTITY_DEFAULT_C_LEVEL.get(hit["label"], c_level)
        identifier = _identifier(hit["label"], hit["value"], entity_level)
        default_action = "allow" if entity_level.upper() in {"C1", "C2"} else "mask"
        action = hit.get("action") or default_action
        mask_preview = _mask_value(hit["value"]) if action == "mask" else None

        hit["identifier"] = identifier
        value_map[identifier] = hit["value"]

        out = out[: hit["start"]] + identifier + out[hit["end"] :]

        entity = {
            "label": hit["label"],
            "span": [hit["start"], hit["end"]],
            "detector": hit["rule_id"],
            "confidence": hit.get("confidence"),
            "confidence_sources": hit.get("confidence_sources", {}),
            "c_level": entity_level,
            "identifier": identifier,
            "action": action,
            "explanation": hit.get("explanation"),
        }
        if mask_preview is not None:
            entity["mask_preview"] = mask_preview

        entities.append(entity)
        receipt_entities.append(
            {
                "identifier": identifier,
                "label": hit["label"],
                "detector": hit["rule_id"],
                "c_level": entity_level,
                "confidence": hit.get("confidence"),
                "confidence_sources": hit.get("confidence_sources", {}),
                "span": [hit["start"], hit["end"]],
                "original": hit["value"],
                "action": action,
                "explanation": hit.get("explanation"),
            }
        )

    public_entities = list(reversed(entities))
    receipt_entities = list(reversed(receipt_entities))

    def _sort_key(item: Dict[str, Any]) -> tuple:
        level = (item.get("c_level") or "C1").upper()
        return (
            -CLEARANCE_ORDER.get(level, 1),
            -(item.get("confidence") or 0.0),
            str(item.get("label")),
            str(item.get("identifier")),
        )

    public_entities_sorted = sorted(public_entities, key=_sort_key)

    operation_id = uuid4().hex
    placeholder_map = {entity["identifier"]: entity["identifier"] for entity in public_entities}
    # --- begin: persist originals to encrypted vault ---
    _vault = Vault()
    vault_items = []
    for entity in entities:
        ident = entity.get("identifier")
        raw_value = value_map.get(ident)
        if ident and raw_value:
            vault_items.append({"identifier": ident, "label": entity.get("label"), "value": raw_value})
    if vault_items:
        try:
            _vault.put_many(operation_id, vault_items)
        except Exception:
            pass
    # --- end: persist originals to encrypted vault ---

    receipt_path = write_receipt(
        operation_id=operation_id,
        text=text,
        scrubbed=out,
        entities=receipt_entities,
        c_level=c_level,
        filename=None,
        policy_version=None,
        placeholder_map=placeholder_map,
    )

    return {
        "original_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "scrubbed": out,
        "scrubbed_ids": out,
        "entities": public_entities_sorted,
        "operation_id": operation_id,
        "receipt_path": str(receipt_path),
    }


__all__ = ["scrub_text", "ENTITY_DEFAULT_C_LEVEL"]
