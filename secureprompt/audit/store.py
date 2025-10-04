from __future__ import annotations

import json, os, time, hashlib, io, threading
from pathlib import Path
from typing import Dict, Iterable, Optional, List
from contextlib import contextmanager

DEFAULT_PATH = Path("data/audit.jsonl")

class AuditStore:
    """
    Minimal append-only JSONL store with a hash chain:
      record['prev_hash'] -> previous line's 'curr_hash'
      record['curr_hash'] -> sha256(prev_hash + stable_json(record_wo_hashes))
    No plaintext secrets should be written by callers.
    """

    def __init__(self, path: os.PathLike | str = DEFAULT_PATH):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

        # ensure file exists with a genesis hash
        if not self.path.exists():
            with self.path.open("w", encoding="utf-8") as f:
                pass

    def _tail_prev_hash(self) -> str:
        """Return the last curr_hash in the file or 64 zeros if empty."""
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "0" * 64
        with self.path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            # read from the end, get last line
            buf = bytearray()
            while size > 0:
                size -= 1
                fh.seek(size)
                b = fh.read(1)
                if b == b"\n" and buf:
                    break
                buf.extend(b)
            line = bytes(reversed(buf)).decode("utf-8", errors="ignore").strip()
        try:
            obj = json.loads(line)
            return obj.get("curr_hash") or ("0"*64)
        except Exception:
            return "0" * 64

    @staticmethod
    def _stable_json(d: Dict) -> str:
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    def append(self, record: Dict) -> Dict:
        """Append record and return the enriched record (with prev/curr hash)."""
        with self._lock:
            prev = self._tail_prev_hash()
            # never hash the hash fields themselves
            base = {k: v for k, v in record.items() if k not in ("prev_hash", "curr_hash")}
            base["ts"] = base.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            payload = dict(base)
            payload["prev_hash"] = prev
            # curr_hash = sha256(prev + stable_json(base))
            curr = hashlib.sha256()
            curr.update(prev.encode("utf-8"))
            curr.update(self._stable_json(base).encode("utf-8"))
            payload["curr_hash"] = curr.hexdigest()

            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False) + "\n")
            return payload

    def stream(self, offset: int = 0, limit: int = 100) -> List[Dict]:
        """Return a slice of records for API pagination."""
        out: List[Dict] = []
        with self.path.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i < offset:
                    continue
                if len(out) >= limit:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out

    def as_bytes(self) -> bytes:
        return self.path.read_bytes() if self.path.exists() else b""
