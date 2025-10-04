from __future__ import annotations

import base64, json, os, time
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.fernet import Fernet, InvalidToken

DEFAULT_DIR = Path("data/vault")


def _load_key() -> bytes:
    """
    Read 32-byte key from env `SECUREPROMPT_VAULT_KEY` (base64 urlsafe).
    If not set, generate a throwaway dev key (safe only for local dev).
    """
    key = os.environ.get("SECUREPROMPT_VAULT_KEY")
    if key:
        try:
            base64.urlsafe_b64decode(key)
            return key.encode("utf-8")
        except Exception:
            pass
    # Dev fallback (warn via comment; do NOT use in prod)
    gen = Fernet.generate_key()
    os.environ["SECUREPROMPT_VAULT_KEY"] = gen.decode("utf-8")
    return gen


class Vault:
    """
    Per-operation encrypted stash. We store ONLY:
      - identifier
      - label (for search)
      - ciphertext  (Fernet)
    File layout: data/vault/{operation_id}.json
    """

    def __init__(self, root: Path | str = DEFAULT_DIR):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.fernet = Fernet(_load_key())

    def _path(self, operation_id: str) -> Path:
        return self.root / f"{operation_id}.json"

    def put_many(self, operation_id: str, items: List[Dict[str, str]]) -> None:
        """
        items: [{"identifier": "...", "label": "EMAIL", "value": "alice@example.com"}, ...]
        """
        path = self._path(operation_id)
        records = []
        now = int(time.time())
        for it in items:
            val = (it.get("value") or "").encode("utf-8")
            records.append({
                "identifier": it["identifier"],
                "label": it.get("label"),
                "ts": now,
                "ciphertext": self.fernet.encrypt(val).decode("utf-8"),
            })
        with path.open("w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)

    def get_map(self, operation_id: str, ids: List[str]) -> Dict[str, str]:
        """
        Return {identifier: plaintext_value} for the requested ids.
        Unknown ids are skipped.
        """
        path = self._path(operation_id)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        wanted = set(ids)
        out: Dict[str, str] = {}
        for row in data:
            ident = row.get("identifier")
            if ident in wanted:
                try:
                    plain = self.fernet.decrypt(row["ciphertext"].encode("utf-8")).decode("utf-8")
                    out[ident] = plain
                except InvalidToken:
                    continue
        return out
