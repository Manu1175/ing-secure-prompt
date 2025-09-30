"""OCR and image utilities."""

from __future__ import annotations

from typing import List, Dict, Any, Tuple

try:  # pragma: no cover - import guard used in tests
    from PIL import Image, ImageDraw
except Exception:  # pragma: no cover
    Image = None
    ImageDraw = None

try:  # pragma: no cover
    import pytesseract
    from pytesseract import TesseractNotFoundError as _TesseractNotFoundError
except Exception:  # pragma: no cover
    pytesseract = None
    _TesseractNotFoundError = RuntimeError


def ocr_image_to_text(img_path: str) -> str:
    """Perform OCR on an image and return the textual content."""

    if pytesseract is None or Image is None:
        raise RuntimeError("pytesseract or Pillow not available; install dependencies")

    try:
        image = Image.open(img_path)
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Failed to open image for OCR") from exc

    try:
        return pytesseract.image_to_string(image)
    except _TesseractNotFoundError as exc:
        raise RuntimeError("Tesseract binary not available") from exc


def redact_image_with_boxes(img_path: str, boxes: List[Tuple[int, int, int, int]], out_path: str) -> Dict[str, Any]:
    """Redact rectangular regions inside an image and persist the output."""

    if Image is None or ImageDraw is None:
        raise RuntimeError("Pillow not available")

    im = Image.open(img_path).convert("RGB")
    draw = ImageDraw.Draw(im)
    for (x1, y1, x2, y2) in boxes:
        draw.rectangle([x1, y1, x2, y2], fill="black")
    im.save(out_path)
    return {"input": img_path, "output": out_path, "boxes": boxes}


__all__ = ["ocr_image_to_text", "redact_image_with_boxes"]
