"""Encrypted receipt persistence for scrub operations."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import hashlib
from cryptography.fernet import Fernet

KEY_ENV = "SP_FERNET_KEY"
KEY_PATH = Path("data/keys/fernet.key")
RECEIPTS_DIR = Path("data/receipts")

_CIPHER: Optional[Fernet] = None


def _load_key() -> bytes:
    env_key = os.environ.get(KEY_ENV)
    if env_key:
        return env_key.encode("utf-8")

    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()

    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    return key


def get_cipher() -> Fernet:
    global _CIPHER
    if _CIPHER is None:
        _CIPHER = Fernet(_load_key())
    return _CIPHER


def encrypt_text(value: str) -> str:
    token = get_cipher().encrypt(value.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_text(token: str) -> str:
    data = get_cipher().decrypt(token.encode("utf-8"))
    return data.decode("utf-8")


def write_receipt(
    *,
    operation_id: str,
    text: str,
    scrubbed: str,
    entities: Iterable[Dict[str, Any]],
    c_level: str,
    filename: Optional[str] = None,
    policy_version: Optional[str] = None,
    placeholder_map: Optional[Dict[str, str]] = None,
) -> Path:
    """Persist encrypted receipt metadata for a scrub operation.

    Parameters
    ----------
    operation_id:
        Unique identifier generated for the scrub run.
    text:
        Original (unsanitised) text snapshot.
    scrubbed:
        Scrubbed text snapshot.
    entities:
        Iterable of entity dictionaries including identifiers and captured spans.
    c_level:
        Clearance level used when scrubbing.
    filename:
        Optional source filename.
    policy_version:
        Optional policy manifest version string.
    placeholder_map:
        Mapping from identifier to placeholder string seen in the scrubbed output.

    Returns
    -------
    Path
        Filesystem path where the receipt JSON was stored.
    """
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)

    original_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    scrubbed_hash = hashlib.sha256(scrubbed.encode("utf-8")).hexdigest()

    serialised_entities = []
    for entity in entities:
        payload = {
            key: entity.get(key)
            for key in (
                "identifier",
                "label",
                "detector",
                "c_level",
                "confidence",
                "span",
                "confidence_sources",
                "explanation",
            )
        }
        if entity.get("excel"):
            payload["excel"] = entity.get("excel")
        original_value = entity.get("original") or entity.get("value") or ""
        payload["original_enc"] = encrypt_text(original_value)
        serialised_entities.append(payload)

    receipt = {
        "operation_id": operation_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hashes": {"original": original_hash, "scrubbed": scrubbed_hash},
        "c_level": c_level,
        "filename": filename,
        "policy_version": policy_version or "unknown",
        "placeholder_map": placeholder_map or {},
        "scrubbed": {"text": scrubbed},
        "entities": serialised_entities,
    }

    path = RECEIPTS_DIR / f"{operation_id}.json"
    receipt["receipt_path"] = str(path)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(receipt, handle, ensure_ascii=False, indent=2)

    return path


def read_receipt(path_or_id: str) -> Dict[str, Any]:
    """Load a stored receipt by path or by operation identifier."""
    candidate = Path(path_or_id)
    if not candidate.exists():
        candidate = RECEIPTS_DIR / f"{path_or_id}.json"
    if not candidate.exists():
        raise FileNotFoundError(f"Receipt not found for {path_or_id}")

    with candidate.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    data.setdefault("receipt_path", str(candidate))
    return data


__all__ = ["get_cipher", "encrypt_text", "decrypt_text", "write_receipt", "read_receipt"]
