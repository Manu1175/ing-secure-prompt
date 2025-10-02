#!/usr/bin/env python3
from __future__ import annotations
import json, sys, glob, os, statistics as stats
from collections import Counter, defaultdict

def main():
    receipts = sorted(glob.glob("data/receipts/*.json"))
    if not receipts:
        print("No receipts found in data/receipts")
        sys.exit(0)
    by_label = Counter()
    by_action = Counter()
    by_clevel = Counter()
    by_detector = Counter()
    confs = defaultdict(list)

    total_entities = 0
    for p in receipts:
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue
        for e in data.get("entities", []):
            total_entities += 1
            lab = e.get("label", "UNKNOWN")
            act = e.get("action", "UNKNOWN")
            clev = e.get("c_level", "C?")
            det = e.get("detector", "unknown")
            conf = float(e.get("confidence", 0) or 0)
            by_label[lab] += 1
            by_action[act] += 1
            by_clevel[clev] += 1
            by_detector[det] += 1
            confs[lab].append(conf)

    out = {
        "files": len(receipts),
        "total_entities": total_entities,
        "labels": by_label.most_common(),
        "actions": by_action.most_common(),
        "c_levels": by_clevel.most_common(),
        "detectors": by_detector.most_common(),
        "confidence_per_label": {
            k: {
                "count": len(v),
                "avg": sum(v)/len(v) if v else 0.0,
                "p50": stats.median(v) if v else 0.0,
                "p90": (sorted(v)[int(0.9*len(v))-1] if v else 0.0)
            } for k, v in confs.items()
        }
    }
    os.makedirs("reports", exist_ok=True)
    with open("reports/scrub_stats.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
