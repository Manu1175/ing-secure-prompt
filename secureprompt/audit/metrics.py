from __future__ import annotations

import glob
import json
import os
import statistics
from pathlib import Path
from typing import Any, Dict


def summarize_metrics(dir_path: str | Path = "data/receipts", limit: int = 2000) -> Dict[str, Any]:
    dir_path = os.environ.get("SECUREPROMPT_RECEIPTS_DIR", str(dir_path))
    root = Path(dir_path)
    files = sorted(glob.glob(str(root / "*.json")))[-limit:]
    by_label: Dict[str, int] = {}
    by_action: Dict[str, int] = {}
    latencies: list[float] = []
    total_ents = 0

    for path in files:
        try:
            rec = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:
            continue

        ents = rec.get("entities") or []
        total_ents += len(ents)
        for entity in ents:
            label = (entity.get("label") or "UNKNOWN").upper()
            by_label[label] = by_label.get(label, 0) + 1
            action = (entity.get("action") or "UNKNOWN").upper()
            by_action[action] = by_action.get(action, 0) + 1

        ms = rec.get("latency_ms") or rec.get("latencyMs")
        if isinstance(ms, (int, float)):
            latencies.append(float(ms))

    latencies.sort()
    p50 = statistics.median(latencies) if latencies else 0
    p90 = latencies[int(0.9 * (len(latencies) - 1))] if latencies else 0

    by_action_no_unknown = {
        k: v for k, v in by_action.items() if k != "UNKNOWN"
    }

    return {
        "receipts": len(files),
        "entities": total_ents,
        "by_label": dict(sorted(by_label.items(), key=lambda kv: -kv[1])[:20]),
        "by_action": dict(sorted(by_action.items(), key=lambda kv: -kv[1])),
        "by_action_no_unknown": dict(sorted(by_action_no_unknown.items(), key=lambda kv: -kv[1])),
        "latency_ms": {
            "p50": int(round(p50)),
            "p90": int(round(p90)),
        },
    }


def summarize(limit: int = 2000) -> Dict[str, Any]:
    return summarize_metrics(limit=limit)
