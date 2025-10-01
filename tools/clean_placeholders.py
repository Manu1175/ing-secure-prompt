from __future__ import annotations
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from typing import Any, Dict, Iterable, List
from pathlib import Path
import yaml

from secureprompt.prompt_mining.validators import is_card_pan, is_india_pan

IN_PATH = Path("policy/placeholders.yml")
OUT_PATH = IN_PATH

def _iter_entries(obj: Any) -> Iterable[Dict[str, Any]]:
    if obj is None:
        return []
    if isinstance(obj, list):
        for e in obj:
            if isinstance(e, dict):
                yield e
        return
    if isinstance(obj, dict):
        for key in ("placeholders", "entries", "items", "data"):
            v = obj.get(key)
            if isinstance(v, list):
                for e in v:
                    if isinstance(e, dict):
                        yield e
                return
        if "label" in obj:
            yield obj
        return

def _load_all(path: Path) -> List[Dict[str, Any]]:
    docs = list(yaml.safe_load_all(path.read_text()))
    out: List[Dict[str, Any]] = []
    for doc in docs:
        out.extend(list(_iter_entries(doc)))
    if not out:
        data = yaml.safe_load(path.read_text())
        if isinstance(data, list):
            out.extend([e for e in data if isinstance(e, dict)])
    return out

def main() -> int:
    if not IN_PATH.exists():
        print("No policy/placeholders.yml found; nothing to clean.")
        return 0

    entries = _load_all(IN_PATH)
    cleaned: List[Dict[str, Any]] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        label = str(entry.get("label", "")).strip()
        examples = [x for x in (entry.get("examples") or []) if isinstance(x, str) and x.strip()]
        base = {k: v for k, v in entry.items() if k not in ("label","examples")}

        if label == "PAN":
            card_vals = [x for x in examples if is_card_pan(x)]
            india_vals = [x for x in examples if is_india_pan(x)]
            if card_vals:
                d = dict(base); d["label"] = "CARD_PAN"; d["c_level"] = "C4"; d["examples"] = card_vals
                cleaned.append(d)
            if india_vals:
                d = dict(base); d["label"] = "IN_PAN"; d["c_level"] = "C4"; d["examples"] = india_vals
                cleaned.append(d)
            if not card_vals and not india_vals:
                d = dict(base); d["label"] = "PAN"; d["examples"] = []
                cleaned.append(d)
        else:
            d = dict(base); d["label"] = label; d["examples"] = examples
            cleaned.append(d)

    OUT_PATH.write_text(yaml.safe_dump(cleaned, sort_keys=False))
    print(f"Cleaned placeholders written to {OUT_PATH}")

    from collections import Counter
    counts = Counter(e.get("label") for e in cleaned if isinstance(e, dict))
    print("Label counts:", dict(counts))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
