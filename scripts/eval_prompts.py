#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import pathlib
from pathlib import Path

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from secureprompt.eval import prompt_eval
from secureprompt.prompt.lexicon import ensure_autolex_from_workbook
from secureprompt.prompt.sanitizer import sanitize_prompt

SAN = sanitize_prompt

print("info: prompt sanitizer active")


def _format_pct(value: float | None) -> str:
    return f"{value * 100:.1f}%" if value is not None else "N/A"


ROOT_DIR = Path(__file__).resolve().parents[1]


def default_in() -> Path:
    prompts_dir = ROOT_DIR / "PROMPTS"
    merged = prompts_dir / "merged.xlsx"
    if merged.is_file():
        return merged
    if prompts_dir.is_dir():
        candidates = sorted(prompts_dir.glob("*.xlsx"))
        if candidates:
            return candidates[0]
    raise FileNotFoundError(
        "No default prompt workbook found. Provide --in or add PROMPTS/merged.xlsx"
    )


def _resolve_input_path(spec: str | Path | None) -> Path:
    if spec is None:
        return default_in()
    candidate = Path(spec)
    if not candidate.exists():
        alt = ROOT_DIR / candidate
        if alt.exists():
            candidate = alt
    if candidate.is_dir():
        merged = candidate / "merged.xlsx"
        if merged.is_file():
            return merged
        files = sorted(candidate.glob("*.xlsx"))
        if files:
            return files[0]
        raise FileNotFoundError(f"No .xlsx files found in directory: {candidate}")
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(f"Input workbook not found: {candidate}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate prompt/response sanitization workbook.")
    parser.add_argument("--in", dest="input_path", help="Path to the input .xlsx workbook or directory")
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

    input_path = _resolve_input_path(args.input_path)
    xlsx_path = input_path

    try:
        auto_path, learned = ensure_autolex_from_workbook(xlsx_path)
        print(f"info: autolex learned {learned} tokens -> {auto_path}")
    except Exception as exc:  # pragma: no cover - defensive guard
        print(f"warn: autolex disabled: {exc}")

    env_clearance = os.getenv("SP_CLEARANCE")
    clearance = (args.clearance or env_clearance or prompt_eval.detect_clearance(input_path)).upper()

    rows = prompt_eval.read_sheet(xlsx_path)
    results = [
        prompt_eval.eval_row(
            row,
            clearance,
            xlsx_hint=xlsx_path,
            style="square",
        )
        for row in rows
    ]
    seen_tokens, matched_tokens = prompt_eval.collect_token_coverage(rows, results)
    summary = prompt_eval.summarize(
        results,
        seen_tokens=seen_tokens,
        matched_tokens=matched_tokens,
    )
    outputs = prompt_eval.write_outputs(input_path, rows, results, summary, output_dir=args.output_dir)

    print(f"Input: {input_path}")
    print(
        "Rows: {rows} | Prompt Acc: {p_acc} | Response Acc: {r_acc} | Entities found: {entities}".format(
            rows=summary.get("total_rows", 0),
            p_acc=_format_pct(summary.get("prompt_accuracy")),
            r_acc=_format_pct(summary.get("response_accuracy")),
            entities=summary.get("total_response_entities", 0),
        )
    )
    print(
        "Outputs: workbook={w} | summary={s} | anomalies={a}".format(
            w=outputs["workbook"],
            s=outputs["summary"],
            a=outputs["anomalies"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
