"""Scoring helpers comparing achieved entities versus baseline expectations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable

from secureprompt.prompt_mining.baseline import load_placeholder_catalog

_BASELINE_ENV = "SECUREPROMPT_BASELINE_PATH"
_PLACEHOLDER_ENV = "SECUREPROMPT_PLACEHOLDERS_PATH"

import os

_DEFAULT_BASELINE_PATH = Path(os.environ.get(_BASELINE_ENV, "reports/baseline_counts.json"))
_PLACEHOLDERS_PATH = Path(os.environ.get(_PLACEHOLDER_ENV, "policy/placeholders.yml"))

_BASELINE_CACHE: Dict[str, Any] | None = None
_LABEL_LEVELS_CACHE: Dict[str, str] | None = None

_CLEARANCE_ORDER = {"C1": 1, "C2": 2, "C3": 3, "C4": 4}


def _ensure_label_levels() -> Dict[str, str]:
    global _LABEL_LEVELS_CACHE
    if _LABEL_LEVELS_CACHE is None:
        _, label_to_level = load_placeholder_catalog(_PLACEHOLDERS_PATH)
        _LABEL_LEVELS_CACHE = label_to_level
    return _LABEL_LEVELS_CACHE


def load_baseline(path: Path | None = None) -> Dict[str, Any]:
    global _BASELINE_CACHE
    if path is None:
        path = _DEFAULT_BASELINE_PATH
    if _BASELINE_CACHE is not None:
        return _BASELINE_CACHE
    if not path.exists():
        _BASELINE_CACHE = {}
    else:
        with path.open("r", encoding="utf-8") as handle:
            _BASELINE_CACHE = json.load(handle)
    return _BASELINE_CACHE


def achieved_counts(entities: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    by_label: Dict[str, int] = {}
    by_level: Dict[str, int] = {}
    for entity in entities or []:
        label = entity.get("label")
        level = (entity.get("c_level") or "C4").upper()
        if label:
            by_label[label] = by_label.get(label, 0) + 1
        by_level[level] = by_level.get(level, 0) + 1
    return {"by_label": by_label, "by_c_level": by_level}


def expected_for_file(
    baseline: Dict[str, Any],
    filename: str,
    clearance: str,
) -> Dict[str, Dict[str, int]]:
    by_file = baseline.get("by_file", {}) if baseline else {}
    file_stats = by_file.get(filename)
    if not file_stats:
        return {"by_label": {}, "by_c_level": {}}

    label_to_level = _ensure_label_levels()
    clearance_rank = _CLEARANCE_ORDER.get(clearance.upper(), 1)

    filtered_by_label: Dict[str, int] = {}
    filtered_by_level: Dict[str, int] = {}

    for label, count in file_stats.get("by_label", {}).items():
        level = label_to_level.get(label, "C4")
        if _CLEARANCE_ORDER.get(level, 4) > clearance_rank:
            filtered_by_label[label] = count
            filtered_by_level[level] = filtered_by_level.get(level, 0) + count

    return {"by_label": filtered_by_label, "by_c_level": filtered_by_level}


def score(
    expected: Dict[str, Dict[str, int]],
    achieved: Dict[str, Dict[str, int]],
) -> Dict[str, Any]:
    exp_labels = expected.get("by_label", {})
    ach_labels = achieved.get("by_label", {})

    if not exp_labels:
        return {"score": 100.0, "diff": {"missing": {}, "extra": {}}}

    contributions = []
    for label, exp in exp_labels.items():
        ach = ach_labels.get(label, 0)
        contributions.append(min(ach, exp) / max(exp, 1))

    overall = (sum(contributions) / len(contributions)) * 100

    missing = {label: max(exp - ach_labels.get(label, 0), 0) for label, exp in exp_labels.items() if exp > ach_labels.get(label, 0)}

    extra = {}
    for label, ach in ach_labels.items():
        exp = exp_labels.get(label, 0)
        if ach > exp:
            extra[label] = ach - exp

    return {"score": round(overall, 2), "diff": {"missing": missing, "extra": extra}}


def reset_cache() -> None:
    global _BASELINE_CACHE, _LABEL_LEVELS_CACHE
    _BASELINE_CACHE = None
    _LABEL_LEVELS_CACHE = None


__all__ = ["load_baseline", "achieved_counts", "expected_for_file", "score", "reset_cache"]
