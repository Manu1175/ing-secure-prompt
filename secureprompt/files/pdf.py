# Text-first extraction using pdfminer.six
def extract_pdf_text(path: str) -> str:
    try:
        from pdfminer.high_level import extract_text
    except Exception as e:
        raise RuntimeError("pdfminer.six not installed") from e
    return extract_text(path) or ""
