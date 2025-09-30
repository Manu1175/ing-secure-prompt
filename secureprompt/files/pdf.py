"""PDF helpers built on top of ``pdfminer.six``."""

from __future__ import annotations

from pathlib import Path

try:  # pragma: no cover - import guard validated in tests
    from pdfminer.high_level import extract_text as _pdf_extract_text
except Exception:  # pragma: no cover
    _pdf_extract_text = None


def extract_pdf_text(path: str | Path) -> str:
    """Extract textual content from a PDF file using ``pdfminer.six``.

    Args:
        path: Path to the PDF file on disk.

    Raises:
        RuntimeError: If ``pdfminer.six`` is not installed or fails to extract.

    Returns:
        The extracted text (empty string when no text is found).
    """

    if _pdf_extract_text is None:
        raise RuntimeError("pdfminer.six not available; install pdfminer.six")

    pdf_path = Path(path)
    try:
        return _pdf_extract_text(str(pdf_path)) or ""
    except Exception as exc:  # pragma: no cover - passthrough error
        raise RuntimeError("Failed to extract PDF text") from exc


__all__ = ["extract_pdf_text"]
