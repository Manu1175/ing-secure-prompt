"""Excel workbook utilities for SecurePrompt."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from openpyxl import load_workbook

from secureprompt.entities.detectors import detect
from secureprompt.receipts.store import write_receipt
from secureprompt.scrub import pipeline as scrub_pipeline
from secureprompt.ui.selective import selective_sanitize


CellKey = Tuple[str, str]


def read_xlsx_text(path: Path) -> List[Dict[str, Any]]:
    """Return non-empty textual cells from a workbook.

    Args:
        path: Absolute path to the workbook on disk.

    Returns:
        A list of dictionaries describing each populated cell. Each dictionary contains
        ``sheet`` (worksheet title), ``cell`` (Excel coordinate), and ``text`` (string
        representation of the cell value).
    """

    workbook = load_workbook(path, read_only=True, data_only=True)
    cells: List[Dict[str, Any]] = []
    try:
        for sheet in workbook.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    value = cell.value
                    if value is None:
                        continue
                    text = str(value).strip()
                    if not text:
                        continue
                    cells.append({"sheet": sheet.title, "cell": cell.coordinate, "text": text})
    finally:
        workbook.close()
    return cells


def write_xlsx_redacted(
    src_path: Path,
    replacements: Dict[CellKey, str],
    *,
    output_path: Optional[Path] = None,
) -> Path:
    """Persist a redacted workbook alongside the source file.

    Args:
        src_path: Path to the source workbook used as a template for redaction.
        replacements: Mapping of ``(sheet, cell)`` to the sanitized text that should
            replace the original cell value.
        output_path: Optional destination for the new workbook. When omitted, the
            redacted workbook is emitted next to ``src_path`` with ``.redacted`` suffix.

    Returns:
        Path to the redacted workbook.
    """

    workbook = load_workbook(src_path)
    try:
        for (sheet_name, cell_ref), text in replacements.items():
            if sheet_name not in workbook.sheetnames:
                continue
            worksheet = workbook[sheet_name]
            worksheet[cell_ref].value = text

        destination = output_path or src_path.with_name(f"{src_path.stem}.redacted{src_path.suffix}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        workbook.save(str(destination))
    finally:
        workbook.close()

    return destination


def _scrub_cell_text(text: str, base_c_level: str = "C4") -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Apply rule-based scrubbing to a single cell value."""

    hits = detect(text)
    transformed = text
    public_entities: List[Dict[str, Any]] = []
    receipt_entities: List[Dict[str, Any]] = []

    for hit in sorted(hits, key=lambda item: item["start"], reverse=True):
        label = hit["label"]
        entity_level = scrub_pipeline.ENTITY_DEFAULT_C_LEVEL.get(label, base_c_level)
        identifier = scrub_pipeline._identifier(label, hit["value"], entity_level)
        action = hit.get("action", "redact")
        mask_preview = scrub_pipeline._mask_value(hit["value"]) if action == "mask" else None

        transformed = transformed[: hit["start"]] + identifier + transformed[hit["end"] :]

        entity = {
            "label": label,
            "span": [hit["start"], hit["end"]],
            "detector": hit["rule_id"],
            "confidence": hit["confidence"],
            "c_level": entity_level,
            "identifier": identifier,
            "action": action,
        }
        if mask_preview is not None:
            entity["mask_preview"] = mask_preview
        public_entities.append(entity)

        receipt_entities.append(
            {
                "identifier": identifier,
                "label": label,
                "detector": hit["rule_id"],
                "c_level": entity_level,
                "confidence": hit["confidence"],
                "span": [hit["start"], hit["end"]],
                "original": hit["value"],
            }
        )

    public_entities.reverse()
    receipt_entities.reverse()
    return transformed, public_entities, receipt_entities


def scrub_workbook(path: Path, clearance: str, *, filename: Optional[str] = None) -> Dict[str, Any]:
    """Scrub an Excel workbook and emit a redacted copy plus an encrypted receipt.

    Args:
        path: Local path to the uploaded workbook (temporary file).
        clearance: Selected clearance for selective masking (C1–C4).
        filename: Optional original filename for logging/receipts.

    Returns:
        A dictionary containing the redaction artefacts:
            ``operation_id``: unique identifier for the scrub
            ``receipt_path``: path to the stored receipt JSON
            ``redacted_path``: path to the redacted workbook
            ``entities``: list of entities suitable for UI display
            ``original_display`` / ``sanitized_display``: newline-joined summaries
    """

    rows = read_xlsx_text(path)
    clearance = clearance.upper()

    combined_original_segments: List[str] = []
    combined_scrubbed_segments: List[str] = []
    display_sanitized_segments: List[str] = []
    placeholder_map: Dict[str, str] = {}
    replacements: Dict[CellKey, str] = {}
    entities_for_ui: List[Dict[str, Any]] = []
    receipt_entities: List[Dict[str, Any]] = []

    for row in rows:
        sheet = row["sheet"]
        cell_ref = row["cell"]
        cell_text = row["text"]

        scrubbed_cell, cell_public_entities, cell_receipt_entities = _scrub_cell_text(cell_text, base_c_level="C4")

        # The persisted workbook should never contain raw sensitive values.
        replacements[(sheet, cell_ref)] = scrubbed_cell
        combined_original_segments.append(f"{sheet}!{cell_ref}={cell_text}")
        combined_scrubbed_segments.append(f"{sheet}!{cell_ref}={scrubbed_cell}")

        sanitized_for_display = selective_sanitize(cell_text, cell_public_entities, clearance)
        if sanitized_for_display == cell_text and scrubbed_cell != cell_text:
            sanitized_for_display = scrubbed_cell
        display_sanitized_segments.append(f"{sheet}!{cell_ref}={sanitized_for_display}")

        for public_entity, receipt_entity in zip(cell_public_entities, cell_receipt_entities):
            excel_meta = {"sheet": sheet, "cell": cell_ref, "offset": receipt_entity["span"]}

            entity_copy = dict(public_entity)
            entity_copy["excel"] = excel_meta
            entities_for_ui.append(entity_copy)

            receipt_copy = dict(receipt_entity)
            receipt_copy["excel"] = excel_meta
            receipt_entities.append(receipt_copy)

            placeholder_map[public_entity["identifier"]] = public_entity["identifier"]

    operation_id = uuid4().hex

    combined_original = "\n".join(combined_original_segments)
    combined_scrubbed = "\n".join(combined_scrubbed_segments)

    receipt_path = write_receipt(
        operation_id=operation_id,
        text=combined_original,
        scrubbed=combined_scrubbed,
        entities=receipt_entities,
        c_level="C4",
        filename=filename,
        policy_version=None,
        placeholder_map=placeholder_map,
    )

    redacted_root = Path("data/redacted") / operation_id
    redacted_root.mkdir(parents=True, exist_ok=True)

    original_name = filename or path.name
    redacted_filename = f"{Path(original_name).stem}.redacted.xlsx"
    redacted_path = write_xlsx_redacted(
        src_path=path,
        replacements=replacements,
        output_path=redacted_root / redacted_filename,
    )

    # Remove the original temporary upload once the redacted artefact is produced.
    try:
        path.unlink()
    except FileNotFoundError:
        pass

    return {
        "operation_id": operation_id,
        "receipt_path": str(receipt_path),
        "redacted_path": str(redacted_path),
        "entities": entities_for_ui,
        "original_display": "\n".join(combined_original_segments),
        "sanitized_display": "\n".join(display_sanitized_segments),
    }


__all__ = ["read_xlsx_text", "write_xlsx_redacted", "scrub_workbook"]
