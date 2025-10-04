#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import json
from typing import Dict, List, Optional

from secureprompt.eval.prompt_eval import evaluate_workbook

def resolve_input(arg: str) -> str:
    if os.path.isdir(arg):
        candidate = os.path.join(arg, "merged.xlsx")
        if os.path.exists(candidate):
            return candidate
        for name in sorted(os.listdir(arg)):
            if name.lower().endswith(".xlsx"):
                return os.path.join(arg, name)
        raise SystemExit(f"No .xlsx found in directory: {arg}")
    return arg

def _load_aliases(path: Optional[str]) -> Optional[Dict[str, str]]:
    if not path:
        default = os.path.join("config", "token_aliases.yml")
        path = default if os.path.exists(default) else None
    if not path:
        return None
    try:
        if path.lower().endswith((".yml", ".yaml")):
            import yaml  # type: ignore
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        if not isinstance(data, dict):
            raise SystemExit(f"Alias file must be a mapping, got: {type(data)}")
        return {str(k): str(v) for k, v in data.items()}
    except ModuleNotFoundError:
        raise SystemExit("PyYAML not installed. Install it or provide a JSON alias file.")
    except Exception as e:
        raise SystemExit(f"Failed to load aliases from {path}: {e}")

def main():
    p = argparse.ArgumentParser(description="Evaluate prompt/response sanitization workbook.")
    p.add_argument("--in", dest="input_path", default="PROMPTS",
                   help="Path to input .xlsx or directory (default: PROMPTS)")
    p.add_argument("--clearance", dest="clearance", default="C3",
                   help="Clearance level, e.g. C3 (default: C3)")
    p.add_argument("--outdir", dest="outdir", default="reports",
                   help="Directory for generated reports (default: reports/)")
    p.add_argument("--no-anomalies-sheet", action="store_true",
                   help="Disable creation of the 'Anomalies' sheet.")
    p.add_argument("--topk", dest="keep_topk", type=int, default=0,
                   help="Keep only the top-K columns (hide the rest). Default 0 (keep all).")
    p.add_argument("--keep-cols", dest="keep_cols", default="",
                   help="Comma-separated list of column names to keep (case-insensitive). Overrides --topk if set.")
    p.add_argument("--diff", dest="diff_mode", default="gold", choices=("gold", "raw", "none"),
                   help="Which diff to compute for Diff_Gold_vs_GotEval. Default: gold.")
    p.add_argument("--eval-source", dest="eval_source", default="auto", choices=("auto","scrubbed","spans"),
                   help="Build Got_Sanitized_Prompt_Eval from: spans, scrubbed tags, or auto fallback. Default: auto.")
    p.add_argument("--aliases", dest="aliases_path", default="",
                   help="Path to alias map (YAML or JSON). If omitted, uses config/token_aliases.yml when present.")
    args = p.parse_args()

    input_path = resolve_input(args.input_path)
    keep_cols: Optional[List[str]] = None
    if args.keep_cols.strip():
        keep_cols = [c.strip() for c in args.keep_cols.split(",") if c.strip()]
    aliases = _load_aliases(args.aliases_path) if (args.aliases_path or os.path.exists("config/token_aliases.yml")) else None

    summary = evaluate_workbook(
        input_path=input_path,
        clearance=args.clearance,
        outdir=args.outdir,
        add_anomalies_sheet=not args.no_anomalies_sheet,
        keep_cols=keep_cols,
        keep_topk=args.keep_topk,
        diff_mode=args.diff_mode,
        eval_source=args.eval_source,
        aliases=aliases,
    )

    print(f"Done. Wrote: {summary['workbook']} and reports/prompt_eval_summary.json")
    pa = round(summary['prompt_accuracy'] * 100.0, 6)
    print(f"Prompt Acc: {pa}% | Response Acc: N/A | Entities found: {summary['total_response_entities']}")

if __name__ == "__main__":
    main()
