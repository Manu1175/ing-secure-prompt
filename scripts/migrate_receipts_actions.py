#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, shutil
from pathlib import Path

# Simple policy: C1/C2 -> allow; PAN/IBAN -> redact; else mask
def policy_action(label: str, c_level: str|None) -> str:
    lab = (label or "").upper()
    clev = (c_level or "").upper()
    if clev.startswith("C1") or clev.startswith("C2"):
        return "allow"
    if lab in ("PAN","IBAN"):
        return "redact"
    return "mask"

def migrate_file(src: Path, dst: Path, dry_run=False) -> bool:
    try:
        rec = json.loads(src.read_text(encoding="utf-8"))
    except Exception:
        return False
    ents = rec.get("entities")
    if not isinstance(ents, list) or not ents:
        return False
    changed = False
    for e in ents:
        a = (e.get("action") or "").strip()
        if not a or a.upper() == "UNKNOWN":
            e["action"] = policy_action(e.get("label"), e.get("c_level"))
            changed = True
    if not changed:
        if dst != src and not dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
        return False
    if not dry_run:
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    return True

def main():
    ap = argparse.ArgumentParser(description="Backfill actions for legacy receipts.")
    ap.add_argument("--in-dir", default="data/receipts")
    ap.add_argument("--out-dir", default="data/receipts_migrated",
                    help="Write migrated copies here. Use --in-place to overwrite originals.")
    ap.add_argument("--in-place", action="store_true", help="Migrate in place (no copies).")
    ap.add_argument("--limit", type=int, default=0, help="Only process last N by name sort.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    in_dir = Path(args.in_dir)
    out_dir = in_dir if args.in_place else Path(args.out_dir)
    paths = sorted(in_dir.glob("*.json"))
    if args.limit and args.limit > 0:
        paths = paths[-args.limit:]
    changed = 0
    for p in paths:
        dst = p if args.in_place else out_dir / p.name
        if migrate_file(p, dst, dry_run=args.dry_run):
            changed += 1
    print(json.dumps({"scanned": len(paths), "changed": changed,
                      "in_place": args.in_place, "out_dir": str(out_dir)}, indent=2))

if __name__ == "__main__":
    main()
