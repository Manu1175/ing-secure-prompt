from __future__ import annotations

from pathlib import Path

import pytest

from secureprompt.files.redact import (
    default_output_path,
    write_redacted_text,
    write_redacted_png,
)

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None


def test_default_output_path_keeps_extension(tmp_path: Path) -> None:
    src = tmp_path / "sample.txt"
    src.write_text("ignored", encoding="utf-8")

    out = default_output_path(src)
    assert out.name == "sample-redacted.txt"


def test_write_redacted_text_uses_default(tmp_path: Path) -> None:
    src = tmp_path / "input.md"
    src.write_text("data", encoding="utf-8")

    out_path = write_redacted_text("redacted", source_path=src)
    assert out_path.exists()
    assert out_path.read_text(encoding="utf-8") == "redacted"
    assert out_path.name == "input-redacted.md"


@pytest.mark.skipif(Image is None, reason="Pillow not available")
def test_write_redacted_png(tmp_path: Path) -> None:
    src = tmp_path / "image.png"
    src.write_bytes(b"")

    image = Image.new("RGB", (2, 2), "white")
    out_path = write_redacted_png(image, source_path=src)

    assert out_path.exists()
    assert out_path.suffix == ".png"
