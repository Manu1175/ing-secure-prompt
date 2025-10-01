from __future__ import annotations
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import yaml, os
from pathlib import Path
from collections import Counter

try:
    from secureprompt.prompt_mining import mine_prompts
except Exception as e:
    print("ERROR: cannot import secureprompt.prompt_mining:", e)
    raise

OUT = Path("policy/placeholders.yml")

def main() -> int:
    src = Path("PROMPTS")
    if not src.exists():
        print("PROMPTS/ not found; nothing to mine.")
        return 0
    mined = mine_prompts(str(src))

    # Normalize to a list of dicts
    entries = []
    for label, data in sorted(mined.items()):
        if not isinstance(data, dict):
            continue
        c_level = data.get("c_level") or "C3"
        templates = sorted({t for t in (data.get("templates") or []) if isinstance(t, str) and t.strip()})
        examples  = sorted({e for e in (data.get("examples") or []) if isinstance(e, str) and e.strip()})
        entries.append({
            "label": str(label),
            "c_level": str(c_level),
            "templates": templates,
            "examples": examples,
        })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(yaml.safe_dump(entries, sort_keys=False))
    print(f"Wrote placeholder catalogue to {OUT}")

    # Compact summary (to stdout only — NOT written into YAML)
    by_label = Counter(e["label"] for e in entries)
    print("Summary (top 10 labels):", by_label.most_common(10))
    for e in entries[:5]:
        print(f"- {e['label']}: c_level={e['c_level']} templates={e.get('templates')[:3]} examples={(e.get('examples') or [])[:1]}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
