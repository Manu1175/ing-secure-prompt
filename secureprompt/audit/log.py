"""Append-only audit logger with JSONL and SQLite mirrors."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = Path("data")
AUDIT_DIR = DATA_DIR / "audit"
DB_PATH = AUDIT_DIR / "audit.db"

_CLEARANCE_ORDER = {"C1": 1, "C2": 2, "C3": 3, "C4": 4}


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _month_jsonl(ts: str) -> Path:
    yyyymm = ts[:7].replace("-", "")
    return AUDIT_DIR / f"audit-{yyyymm}.jsonl"


def _ensure_db() -> sqlite3.Connection:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          event TEXT NOT NULL,
          operation_id TEXT,
          prev_hash TEXT,
          hash TEXT,
          json TEXT NOT NULL
        );
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON audit(ts);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_op ON audit(operation_id);")
    conn.commit()
    return conn


def last_hash() -> Optional[str]:
    conn = _ensure_db()
    try:
        cur = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1;")
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _canon(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _chain_hash(prev: Optional[str], event_obj: Dict[str, Any]) -> str:
    base = (prev or "") + "\n" + _canon(event_obj)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def append(event: Dict[str, Any]) -> Dict[str, Any]:
    """Append an event to the audit trail and return the enriched payload."""

    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    ts = event.setdefault("ts", _now_iso())
    prev = event.setdefault("prev_hash", last_hash())
    h = _chain_hash(prev, event)
    event["hash"] = h

    jsonl = _month_jsonl(ts)
    with jsonl.open("a", encoding="utf-8") as handle:
        handle.write(_canon(event) + "\n")

    conn = _ensure_db()
    try:
        conn.execute(
            "INSERT INTO audit(ts,event,operation_id,prev_hash,hash,json) VALUES(?,?,?,?,?,?)",
            (
                ts,
                event.get("event"),
                event.get("operation_id"),
                prev,
                h,
                _canon(event),
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return event


def tail(n: int = 200) -> List[Dict[str, Any]]:
    conn = _ensure_db()
    try:
        cur = conn.execute("SELECT json FROM audit ORDER BY id DESC LIMIT ?;", (n,))
        rows = [json.loads(row[0]) for row in cur.fetchall()]
        return rows
    finally:
        conn.close()


def find_by_operation(operation_id: str) -> List[Dict[str, Any]]:
    conn = _ensure_db()
    try:
        cur = conn.execute(
            "SELECT json FROM audit WHERE operation_id=? ORDER BY id ASC;",
            (operation_id,),
        )
        rows = [json.loads(row[0]) for row in cur.fetchall()]
        return rows
    finally:
        conn.close()


def summarize_entities(entities: List[Dict[str, Any]], clearance: str) -> Dict[str, Any]:
    clearance_rank = _CLEARANCE_ORDER.get((clearance or "C1").upper(), 1)
    labels = Counter()
    levels = Counter()
    masked = 0

    for entity in entities or []:
        label = entity.get("label")
        level = (entity.get("c_level") or "C4").upper()
        if label:
            labels[label] += 1
        levels[level] += 1
        if _CLEARANCE_ORDER.get(level, 4) > clearance_rank:
            masked += 1

    total = sum(labels.values()) if labels else sum(levels.values())
    return {
        "entities_total": total,
        "masked": masked,
        "by_label": dict(labels),
        "by_c_level": dict(levels),
    }


def jsonl_path(ts: Optional[str] = None) -> Path:
    return _month_jsonl(ts or _now_iso())


__all__ = [
    "append",
    "tail",
    "find_by_operation",
    "last_hash",
    "summarize_entities",
    "jsonl_path",
]
