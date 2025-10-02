#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

from secureprompt.eval import prompt_eval


def _format_pct(value: float | None) -> str:
    return f"{value * 100:.1f}%" if value is not None else "N/A"


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate prompt/response sanitization workbook.")
    parser.add_argument("--in", dest="input_path", required=True, help="Path to the input .xlsx workbook")
    parser.add_argument(
        "--clearance",
        dest="clearance",
        help="Override clearance level (defaults to env SP_CLEARANCE or inferred from filename)",
    )
    parser.add_argument(
        "--outdir",
        dest="output_dir",
        default="reports",
        help="Directory for generated reports (default: reports/)",
    )
    args = parser.parse_args()

    input_path = Path(args.input_path)
    if not input_path.is_file():
        raise FileNotFoundError(f"Input workbook not found: {input_path}")

    env_clearance = os.getenv("SP_CLEARANCE")
    clearance = (args.clearance or env_clearance or prompt_eval.detect_clearance(input_path)).upper()

    rows = prompt_eval.read_sheet(input_path)
    results = [prompt_eval.eval_row(row, clearance) for row in rows]
    summary = prompt_eval.summarize(results)
    outputs = prompt_eval.write_outputs(input_path, rows, results, summary, output_dir=args.output_dir)

    print(
        "Rows: {rows} | Prompt Acc: {p_acc} | Response Acc: {r_acc} | Entities found: {entities}".format(
            rows=summary.get("total_rows", 0),
            p_acc=_format_pct(summary.get("prompt_accuracy")),
            r_acc=_format_pct(summary.get("response_accuracy")),
            entities=summary.get("total_response_entities", 0),
        )
    )
    print(f"Workbook: {outputs['workbook']}")
    print(f"Summary: {outputs['summary']}")
    print(f"Anomalies: {outputs['anomalies']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
