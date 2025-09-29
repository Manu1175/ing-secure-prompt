import os, json, hashlib, time
from pathlib import Path
from typing import Dict, Any

class AuditLog:
    def __init__(self, path: str="data/audit.log"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("")
        self._last_hash = self._tail_hash()

    def _tail_hash(self) -> str:
        try:
            *_, last = self.path.read_text().splitlines()
            return json.loads(last).get("curr_hash", "")
        except Exception:
            return ""

    def append(self, record: Dict[str, Any]) -> str:
        prev = self._last_hash
        payload = json.dumps(record, sort_keys=True)
        curr = hashlib.sha256((prev + payload).encode("utf-8")).hexdigest()
        entry = {"ts": time.time(), "prev_hash": prev, "curr_hash": curr, **record}
        with self.path.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        self._last_hash = curr
        return curr
