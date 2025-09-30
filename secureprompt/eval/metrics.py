"""Metrics utilities for SecurePrompt golden dataset evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from secureprompt.scrub.pipeline import scrub_text

OUTPUT_TEXT_CANDIDATES = (
    "text",
    "scrubbed_text",
    "scrubbed",
    "output",
    "scrubbed_output",
)


@dataclass
class LabelMetrics:
    """Mutable aggregation container for per-label statistics."""

    label: str
    n: int = 0
    residual_hits: int = 0
    total_sensitive: int = 0
    replaced: int = 0
    exact_matches: int = 0
    expected_with_value: int = 0
    missing_expected: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "n": self.n,
            "residual_hits": self.residual_hits,
            "replaced": self.replaced,
            "exact_matches": self.exact_matches,
            "recall": self.recall,
            "notes": self.notes,
        }

    @property
    def recall(self) -> float:
        if self.total_sensitive == 0:
            return 0.0
        return self.residual_hits / self.total_sensitive

    @property
    def notes(self) -> str:
        notes: List[str] = []
        if self.missing_expected:
            notes.append(f"{self.missing_expected} missing expected")
        if self.total_sensitive == 0:
            notes.append("no sensitive entities")
        return "; ".join(notes)

    def merge(self, other: "LabelMetrics") -> None:
        self.n += other.n
        self.residual_hits += other.residual_hits
        self.total_sensitive += other.total_sensitive
        self.replaced += other.replaced
        self.exact_matches += other.exact_matches
        self.expected_with_value += other.expected_with_value
        self.missing_expected += other.missing_expected


def evaluate_golden(
    *,
    data_dir: Optional[Path] = None,
    report_path: Optional[Path] = None,
    scrubber: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Evaluate golden JSONL fixtures and write a markdown report.

    Args:
        data_dir: Directory containing ``*.jsonl`` golden files. Defaults to
            ``<repo>/data/golden``.
        report_path: Destination for the markdown report. Defaults to
            ``<repo>/reports/metrics.md``.
        scrubber: Callable compatible with ``scrub_text`` used to transform raw
            text. Defaults to the production pipeline.

    Returns:
        A dictionary containing per-label summaries and overall totals.
    """

    scrubber = scrubber or scrub_text

    repo_root = Path(__file__).resolve().parents[2]
    data_dir = Path(data_dir) if data_dir is not None else repo_root / "data" / "golden"
    report_path = (
        Path(report_path)
        if report_path is not None
        else repo_root / "reports" / "metrics.md"
    )

    label_metrics: Dict[str, LabelMetrics] = {}
    overall = LabelMetrics(label="overall")

    for jsonl_path in sorted(data_dir.glob("*.jsonl")):
        with jsonl_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                label = str(record.get("label", "unknown"))
                metrics = label_metrics.setdefault(label, LabelMetrics(label=label))
                _update_metrics(metrics, record, scrubber)

    for metrics in label_metrics.values():
        overall.merge(metrics)

    _write_report(report_path, label_metrics, overall)

    return {
        "by_label": {label: metrics.as_dict() for label, metrics in label_metrics.items()},
        "overall": overall.as_dict(),
    }


def _update_metrics(
    metrics: LabelMetrics,
    record: Dict[str, Any],
    scrubber: Callable[[str], Dict[str, Any]],
) -> None:
    raw_text = record.get("raw_text", "")
    metrics.n += 1

    sensitive_values = _collect_sensitive_values(record)
    metrics.total_sensitive += len(sensitive_values)

    result = scrubber(raw_text)
    output_text = _extract_output_text(result)

    residual_hits = sum(1 for value in sensitive_values if value and value in output_text)
    metrics.residual_hits += residual_hits

    entities = result.get("entities") if isinstance(result, dict) else None
    metrics.replaced += len(entities) if isinstance(entities, list) else 0

    expected_scrub = record.get("expected_scrub")
    if expected_scrub is None:
        metrics.missing_expected += 1
    else:
        metrics.expected_with_value += 1
        if output_text == expected_scrub:
            metrics.exact_matches += 1


def _collect_sensitive_values(record: Dict[str, Any]) -> List[str]:
    candidates: Iterable[Any] = record.get("expected_entities", record.get("entities", []))
    values: List[str] = []
    for item in candidates:
        if isinstance(item, str):
            values.append(item)
            continue
        if isinstance(item, dict):
            for key in ("value", "text", "raw", "original"):
                if key in item and isinstance(item[key], str):
                    values.append(item[key])
                    break
    return values


def _extract_output_text(result: Dict[str, Any]) -> str:
    if not isinstance(result, dict):
        return str(result)
    for key in OUTPUT_TEXT_CANDIDATES:
        value = result.get(key)
        if isinstance(value, str):
            return value
    # Fallback: use first string value if present
    for value in result.values():
        if isinstance(value, str):
            return value
    return ""


def _write_report(
    report_path: Path,
    label_metrics: Dict[str, LabelMetrics],
    overall: LabelMetrics,
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)

    headers = [
        "label",
        "n",
        "residual_hits",
        "replaced",
        "exact_matches",
        "recall",
        "notes",
    ]

    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]

    for label in sorted(label_metrics):
        metrics = label_metrics[label].as_dict()
        lines.append(_format_row(metrics))

    lines.append(_format_row(overall.as_dict()))

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _format_row(metrics: Dict[str, Any]) -> str:
    recall = f"{metrics.get('recall', 0.0):.3f}"
    return (
        f"| {metrics.get('label', '')} | {metrics.get('n', 0)} | {metrics.get('residual_hits', 0)} | "
        f"{metrics.get('replaced', 0)} | {metrics.get('exact_matches', 0)} | {recall} | {metrics.get('notes', '')} |"
    )


__all__ = ["evaluate_golden"]
