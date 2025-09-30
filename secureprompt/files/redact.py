"""Helpers for writing redacted artefacts to disk."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:  # pragma: no cover - optional dependency
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None  # type: ignore[assignment]


def default_output_path(
    source_path: str | Path,
    *,
    suffix: str = "-redacted",
    extension: Optional[str] = None,
) -> Path:
    """Return a default output path derived from ``source_path``."""

    src = Path(source_path)
    ext = extension if extension is not None else (src.suffix or ".txt")
    return src.with_name(f"{src.stem}{suffix}{ext}")


def write_redacted_text(
    content: str,
    *,
    source_path: str | Path,
    output_path: str | Path | None = None,
) -> Path:
    """Persist redacted text to disk and return the output path."""

    path = Path(output_path) if output_path else default_output_path(source_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def write_redacted_png(
    image: "Image.Image",
    *,
    source_path: str | Path,
    output_path: str | Path | None = None,
) -> Path:
    """Save a redacted PNG image using Pillow."""

    if Image is None:
        raise RuntimeError("Pillow not available")

    path = Path(output_path) if output_path else default_output_path(source_path, extension=".png")
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, format="PNG")
    return path


__all__ = ["default_output_path", "write_redacted_text", "write_redacted_png"]

