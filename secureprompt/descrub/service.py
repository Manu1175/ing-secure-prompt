from __future__ import annotations

import json, re
from pathlib import Path
from typing import Dict, List, Tuple
from secureprompt.audit.vault import Vault

RECEIPTS = Path("data/receipts")


def _load_receipt(operation_id: str) -> Dict:
    p = RECEIPTS / f"{operation_id}.json"
    if not p.exists():
        raise FileNotFoundError(operation_id)
    return json.loads(p.read_text(encoding="utf-8"))


def _replace_identifiers(text: str, mapping: Dict[str, str]) -> str:
    """
    Replace occurrences of 'Ck::LABEL::hash' with original values for the chosen ids only.
    """
    if not mapping:
        return text
    # Build one big alternation for speed; identifiers contain only safe chars
    alts = "|".join(re.escape(k) for k in mapping.keys())
    rx = re.compile(alts)
    return rx.sub(lambda m: mapping[m.group(0)], text)


def descrub(operation_id: str, identifiers: List[str]) -> Tuple[str, Dict]:
    """
    Returns (descrubbed_text, context) using 'scrubbed_ids' from the receipt as base.
    """
    vault = Vault()
    rec = _load_receipt(operation_id)
    base = rec.get("scrubbed_ids") or rec.get("scrubbed") or ""
    if isinstance(base, dict) and "text" in base:
        base = base.get("text") or ""
    if not isinstance(base, str):
        base = str(base)
    requested = identifiers or [
        entry.get("identifier")
        for entry in (rec.get("entities") or [])
        if entry.get("identifier")
    ]
    mapping = vault.get_map(operation_id, requested)
    return _replace_identifiers(base, mapping), {"restored": list(mapping.keys())}
