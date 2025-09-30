from pathlib import Path
import inspect
from secureprompt.eval.metrics import evaluate_golden

sig = inspect.signature(evaluate_golden)
metrics = evaluate_golden() if len(sig.parameters)==0 else evaluate_golden("data/golden")

def render_md(m: dict) -> str:
    per = m.get("per_label") or m.get("labels") or {}
    overall = m.get("overall", {})
    lines = [
        "# Metrics",
        "",
        "| label | n | residual_hits | replaced | exact_matches | recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, row in sorted(per.items()):
        n, rh, rep, em, rec = (row.get("n",0), row.get("residual_hits",0),
                               row.get("replaced",0), row.get("exact_matches",0),
                               row.get("recall",0.0))
        lines.append(f"| {label} | {n} | {rh} | {rep} | {em} | {rec:.3f} |")
    if overall:
        n, rh, rep, em, rec = (overall.get("n",0), overall.get("residual_hits",0),
                               overall.get("replaced",0), overall.get("exact_matches",0),
                               overall.get("recall",0.0))
        lines.append(f"| overall | {n} | {rh} | {rep} | {em} | {rec:.3f} |")
    return "\n".join(lines) + "\n"

Path("reports").mkdir(parents=True, exist_ok=True)
Path("reports/metrics.md").write_text(render_md(metrics), encoding="utf-8")
print("✅ Wrote reports/metrics.md")
