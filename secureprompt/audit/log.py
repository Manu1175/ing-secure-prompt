"""Simple append-only audit log with hash chaining."""

from __future__ import annotations

import json
import hashlib
import time
from pathlib import Path
from typing import Dict, Any


class AuditLog:
    """Append-only audit logger that maintains a tamper-evident hash chain."""

    def __init__(self, path: str = "data/audit.log") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        self._last_hash = self._tail_hash()

    def _tail_hash(self) -> str:
        """Return the last ``curr_hash`` stored in the log."""

        try:
            *_, last = self.path.read_text(encoding="utf-8").splitlines()
            return json.loads(last).get("curr_hash", "")
        except Exception:
            return ""

    def append(self, record: Dict[str, Any]) -> str:
        """Append ``record`` to the log and return the new chain hash."""

        prev = self._last_hash
        payload = json.dumps(record, sort_keys=True)
        curr = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
        entry = {"ts": time.time(), "prev_hash": prev, "curr_hash": curr, **record}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
        self._last_hash = curr
        return curr


__all__ = ["AuditLog"]
