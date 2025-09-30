from typing import List, Dict, Any, Tuple

try:  # pragma: no cover - import guard used in tests
    from PIL import Image, ImageDraw
except Exception:  # pragma: no cover
    Image = None
    ImageDraw = None

try:  # pragma: no cover
    import pytesseract
except Exception:  # pragma: no cover
    pytesseract = None

def ocr_image_to_text(img_path: str) -> str:
    if pytesseract is None:
        raise RuntimeError("pytesseract not available; install Tesseract and pytesseract.")
    return pytesseract.image_to_string(Image.open(img_path))

def redact_image_with_boxes(img_path: str, boxes: List[Tuple[int,int,int,int]], out_path: str) -> Dict[str, Any]:
    if Image is None or ImageDraw is None:
        raise RuntimeError("Pillow not available")
    im = Image.open(img_path).convert("RGB")
    draw = ImageDraw.Draw(im)
    for (x1,y1,x2,y2) in boxes:
        draw.rectangle([x1,y1,x2,y2], fill="black")
    im.save(out_path)
    return {"input": img_path, "output": out_path, "boxes": boxes}
