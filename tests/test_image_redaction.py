import os
from PIL import Image, ImageDraw
from secureprompt.files.ocr import redact_image_with_boxes

def test_image_redaction(tmp_path):
    p = tmp_path / "in.png"
    im = Image.new("RGB", (200, 100), "white")
    d = ImageDraw.Draw(im)
    d.text((10,40), "SECRET", fill="black")
    im.save(p)
    out = tmp_path / "out.png"
    res = redact_image_with_boxes(str(p), [(5,35,120,65)], str(out))
    assert os.path.exists(out)
    assert res["boxes"] == [(5,35,120,65)]
