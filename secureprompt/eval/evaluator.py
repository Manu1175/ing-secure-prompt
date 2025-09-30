"""Golden set evaluation helpers."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from secureprompt.scrub.pipeline import scrub_text


@dataclass(frozen=True)
class EntityKey:
    """Unique identifier for an entity instance within a record."""

    label: str
    start: Optional[int]
    end: Optional[int]


@dataclass
class EntityCollection:
    """Normalized entity annotations for a record."""

    entries: List[EntityKey]
    has_spans: bool

    @property
    def labels(self) -> Iterable[str]:
        """Iterate over labels without exposing span details."""
        return (entry.label for entry in self.entries)


def _coerce_entities(raw: Any) -> List[Any]:
    """Coerce entity annotations to a list of dict-like objects."""

    if raw in (None, ""):
        return []
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parts = [segment.strip() for segment in text.split(",") if segment.strip()]
            return [{"label": part} for part in parts]
        return _coerce_entities(parsed)
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return raw
    return []


def _extract_span(candidate: Any) -> EntityKey:
    """Build an EntityKey from a raw annotation candidate."""

    if not isinstance(candidate, dict):
        return EntityKey(label=str(candidate).upper(), start=None, end=None)
    label = (candidate.get("label") or candidate.get("entity") or "").upper()
    span = candidate.get("span")
    start: Optional[int] = None
    end: Optional[int] = None
    if isinstance(span, (list, tuple)) and len(span) == 2:
        try:
            start = int(span[0])
            end = int(span[1])
        except (TypeError, ValueError):
            start, end = None, None
    if start is None or end is None:
        try:
            start = int(candidate.get("start")) if candidate.get("start") is not None else None
            end = int(candidate.get("end")) if candidate.get("end") is not None else None
        except (TypeError, ValueError):
            start, end = None, None
    return EntityKey(label=label, start=start, end=end)


def _collect_entities(raw: Any) -> EntityCollection:
    """Normalize arbitrary entity annotations into EntityCollection."""

    entries = [_extract_span(item) for item in _coerce_entities(raw)]
    has_spans = bool(entries) and all(entry.start is not None and entry.end is not None for entry in entries)
    return EntityCollection(entries=entries, has_spans=has_spans)


def _count_entities(collection: EntityCollection, use_spans: bool) -> Dict[str, Counter]:
    """Group entity occurrences per label using span-aware or label-only keys."""

    grouped: Dict[str, Counter] = defaultdict(Counter)
    for entry in collection.entries:
        key = (entry.start, entry.end) if use_spans else "__any__"
        grouped[entry.label][key] += 1
    return grouped


def _compare_entities(expected: EntityCollection, predicted: EntityCollection) -> Dict[str, Dict[str, int]]:
    """Compute per-label tp/fp/fn counts for a single record."""

    use_spans = expected.has_spans and predicted.has_spans
    expected_counts = _count_entities(expected, use_spans)
    predicted_counts = _count_entities(predicted, use_spans)
    labels = set(expected_counts) | set(predicted_counts)
    stats: Dict[str, Dict[str, int]] = {}
    for label in labels:
        exp = expected_counts.get(label, Counter())
        pred = predicted_counts.get(label, Counter())
        keys = set(exp) | set(pred)
        tp = sum(min(pred[k], exp[k]) for k in keys)
        fp = sum(max(0, pred[k] - exp[k]) for k in keys)
        fn = sum(max(0, exp[k] - pred[k]) for k in keys)
        stats[label] = {"tp": tp, "fp": fp, "fn": fn}
    return stats


def _safe_div(numerator: int, denominator: int) -> Optional[float]:
    """Compute a safe division, returning None when the denominator is zero."""
    return numerator / denominator if denominator else None


def _format_score(score: Optional[float]) -> str:
    """Render a metric score into a markdown-friendly string."""
    return f"{score:.3f}" if score is not None else "-"


def _render_table(metrics: Dict[str, Any]) -> str:
    lines: List[str] = ["# Metrics", ""]
    total_records = metrics.get("record_count", 0)
    evaluated = metrics.get("evaluated_records", total_records)
    lines.append(f"Evaluated {evaluated} of {total_records} golden records.")
    lines.append("")
    lines.append("| Label | Precision | Recall | TP | FP | FN |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for label in metrics.get("label_order", []):
        data = metrics["per_label"][label]
        lines.append(
            f"| {label} | {_format_score(data['precision'])} | {_format_score(data['recall'])} | "
            f"{data['tp']} | {data['fp']} | {data['fn']} |"
        )
    overall = metrics["overall"]
    lines.append(
        f"| Overall | {_format_score(overall['precision'])} | {_format_score(overall['recall'])} | "
        f"{overall['tp']} | {overall['fp']} | {overall['fn']} |"
    )
    return "\n".join(lines) + "\n"


def load_golden_records(golden_dir: Path) -> List[Dict[str, Any]]:
    """Load all golden jsonl records from a directory."""

    records: List[Dict[str, Any]] = []
    for path in sorted(Path(golden_dir).glob("*.jsonl")):
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                payload = line.strip()
                if not payload:
                    continue
                try:
                    records.append(json.loads(payload))
                except json.JSONDecodeError:
                    continue
    return records


def evaluate_golden(
    golden_dir: Path = Path("data/golden"),
    report_path: Path = Path("reports/metrics.md"),
) -> Dict[str, Any]:
    """Evaluate scrubber precision/recall against the golden set and update metrics."""

    records = load_golden_records(golden_dir)
    totals: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    evaluated_records = 0
    for record in records:
        raw_text = record.get("raw_text")
        if not isinstance(raw_text, str) or not raw_text.strip():
            continue
        c_level = record.get("c_level") or "C3"
        expected = _collect_entities(record.get("entities"))
        result = scrub_text(raw_text, c_level)
        predicted = _collect_entities(result.get("entities"))
        label_stats = _compare_entities(expected, predicted)
        for label, counts in label_stats.items():
            slot = totals[label]
            slot["tp"] += counts["tp"]
            slot["fp"] += counts["fp"]
            slot["fn"] += counts["fn"]
        evaluated_records += 1

    per_label: Dict[str, Dict[str, Any]] = {}
    overall_tp = overall_fp = overall_fn = 0
    for label in sorted(totals):
        counts = totals[label]
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        per_label[label] = {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall}
        overall_tp += tp
        overall_fp += fp
        overall_fn += fn

    overall_precision = _safe_div(overall_tp, overall_tp + overall_fp)
    overall_recall = _safe_div(overall_tp, overall_tp + overall_fn)
    metrics = {
        "record_count": len(records),
        "evaluated_records": evaluated_records,
        "per_label": per_label,
        "label_order": sorted(per_label),
        "overall": {
            "tp": overall_tp,
            "fp": overall_fp,
            "fn": overall_fn,
            "precision": overall_precision,
            "recall": overall_recall,
        },
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(_render_table(metrics), encoding="utf-8")
    return metrics


if __name__ == "__main__":
    evaluate_golden()
