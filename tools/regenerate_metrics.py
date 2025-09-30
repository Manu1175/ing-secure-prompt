# tools/regenerate_metrics.py
"""
Regenerate the markdown metrics report from the golden set.

Usage (from repo root, venv active):
    PYTHONPATH=. python tools/regenerate_metrics.py [data/golden]

This script is resilient to different `evaluate_golden` signatures:
- No-arg:                 def evaluate_golden() -> dict
- Keyword-only `base_dir`: def evaluate_golden(*, base_dir="data/golden") -> dict
- Positional/keyword arg: def evaluate_golden(base_dir="data/golden") -> dict
"""

from __future__ import annotations

import sys
import inspect
from pathlib import Path
from typing import Dict, Any

from secureprompt.eval.metrics import evaluate_golden


def _compute_metrics(base_dir: str = "data/golden") -> Dict[str, Any]:
    """
    Call `evaluate_golden` regardless of its signature variant.
    """
    sig = inspect.signature(evaluate_golden)
    params = list(sig.parameters.values())

    # Case 1: no parameters at all
    if not params:
        return evaluate_golden()  # type: ignore[misc]

    # Case 2: choose the first "real" param (pos-only, pos-or-kw, or kw-only)
    for p in params:
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY):
            # Prefer keyword call to satisfy kw-only signatures
            try:
                return evaluate_golden(**{p.name: base_dir})  # type: ignore[misc]
            except TypeError:
                # Fall back to positional if keyword fails
                return evaluate_golden(base_dir)  # type: ignore[misc]

    # Fallback: try positional once
    return evaluate_golden(base_dir)  # type: ignore[misc]


def _render_md(metrics: Dict[str, Any]) -> str:
    """
    Render a compact markdown table from the metrics dict.
    Expected shapes supported:
      { "per_label": {...}, "overall": {...} }  or
      { "labels": {...},    "overall": {...} }
    """
    per = (
        metrics.get("per_label")
        or metrics.get("by_label")
        or metrics.get("labels")
        or {}
    )
    overall = metrics.get("overall", {})

    lines = [
        "# Metrics",
        "",
        "| label | n | residual_hits | replaced | exact_matches | recall | notes |",
        "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]

    for label, row in sorted(per.items()):
        n = row.get("n", 0)
        rh = row.get("residual_hits", 0)
        rep = row.get("replaced", 0)
        em = row.get("exact_matches", 0)
        rec = row.get("recall", 0.0)
        notes = row.get("notes", "")
        lines.append(f"| {label} | {n} | {rh} | {rep} | {em} | {rec:.3f} | {notes} |")

    if overall:
        n = overall.get("n", 0)
        rh = overall.get("residual_hits", 0)
        rep = overall.get("replaced", 0)
        em = overall.get("exact_matches", 0)
        rec = overall.get("recall", 0.0)
        notes = overall.get("notes", "")
        lines.append(f"| overall | {n} | {rh} | {rep} | {em} | {rec:.3f} | {notes} |")

    return "\n".join(lines) + "\n"


def main() -> None:
    base_dir = sys.argv[1] if len(sys.argv) > 1 else "data/golden"
    metrics = _compute_metrics(base_dir)
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.md").write_text(_render_md(metrics), encoding="utf-8")
    print("✅ Wrote reports/metrics.md")


if __name__ == "__main__":
    main()
