import pytest
def test_pdf_extract_import_only():
    try:
        from secureprompt.files.pdf import extract_pdf_text
    except Exception:
        pytest.skip("pdfminer not installed; skip")
