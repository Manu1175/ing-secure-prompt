from __future__ import annotations

from pathlib import Path

import pytest

from secureprompt.files.text import load_text
from secureprompt.files import pdf as pdf_module
from secureprompt.files import ocr as ocr_module


def test_load_text_plain(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello world", encoding="utf-8")

    assert load_text(file_path) == "hello world"


def test_load_text_html(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.html"
    file_path.write_text("<html><body><h1>Title</h1><p>Content</p></body></html>", encoding="utf-8")

    assert load_text(file_path) == "Title Content"


def test_load_text_csv(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.csv"
    file_path.write_text("a,b\n1,2", encoding="utf-8")

    assert load_text(file_path) == "a\tb\n1\t2"


def test_extract_pdf_text_missing_dependency(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pdf_file = tmp_path / "dummy.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n%%EOF")

    monkeypatch.setattr(pdf_module, "_pdf_extract_text", None)

    with pytest.raises(RuntimeError):
        pdf_module.extract_pdf_text(pdf_file)


def test_extract_pdf_text_happy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pdf_file = tmp_path / "dummy.pdf"
    pdf_file.write_bytes(b"%PDF-1.4\n%%EOF")

    monkeypatch.setattr(pdf_module, "_pdf_extract_text", lambda path: "PDF content")

    assert pdf_module.extract_pdf_text(pdf_file) == "PDF content"


def test_ocr_image_to_text_missing_dependency(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ocr_module, "pytesseract", None)

    with pytest.raises(RuntimeError):
        ocr_module.ocr_image_to_text(str(tmp_path / "missing.png"))


def test_ocr_image_to_text_happy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    if ocr_module.pytesseract is None or ocr_module.Image is None:
        pytest.skip("OCR dependencies unavailable")

    image_path = tmp_path / "img.png"
    ocr_module.Image.new("RGB", (10, 10), "white").save(image_path)

    def fake_image_to_string(image):  # pragma: no cover - trivial
        return "decoded"

    monkeypatch.setattr(ocr_module.pytesseract, "image_to_string", fake_image_to_string)

    try:
        version = ocr_module.pytesseract.get_tesseract_version()
    except Exception:
        pytest.skip("Tesseract binary missing")

    assert ocr_module.ocr_image_to_text(str(image_path)) == "decoded"
