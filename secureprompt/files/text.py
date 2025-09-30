"""Utilities for loading plain-text friendly files."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
import csv


class _HTMLBodyExtractor(HTMLParser):
    """Simple HTML parser that collects textual content."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._skip_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: Iterable[tuple[str, str]]) -> None:  # pragma: no cover - trivial
        if tag in {"script", "style"}:
            self._skip_stack.append(tag)

    def handle_endtag(self, tag: str) -> None:  # pragma: no cover - trivial
        if self._skip_stack and self._skip_stack[-1] == tag:
            self._skip_stack.pop()

    def handle_data(self, data: str) -> None:
        if self._skip_stack:
            return
        if data.strip():
            self._chunks.append(data.strip())

    def get_text(self) -> str:
        return " ".join(self._chunks)


def load_text(path: str | Path) -> str:
    """Return text content from ``txt``, ``html``, or ``csv`` files.

    Args:
        path: File path that should resolve to a readable file.

    Raises:
        ValueError: If the suffix is unsupported.
        FileNotFoundError: If the file does not exist.

    Returns:
        The textual contents as a single string.
    """

    file_path = Path(path)
    suffix = file_path.suffix.lower()

    if suffix in {".txt", ".text", ""}:
        return file_path.read_text(encoding="utf-8")

    if suffix in {".html", ".htm"}:
        parser = _HTMLBodyExtractor()
        parser.feed(file_path.read_text(encoding="utf-8"))
        return parser.get_text()

    if suffix == ".csv":
        rows: list[str] = []
        with file_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            for row in reader:
                rows.append("\t".join(row))
        return "\n".join(rows)

    raise ValueError(f"Unsupported file type for load_text: {suffix or '<no suffix>'}")


__all__ = ["load_text"]

