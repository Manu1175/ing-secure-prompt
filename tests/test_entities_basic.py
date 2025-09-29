from secureprompt.entities.detectors import detect

def test_email_and_iban_detection():
    text = "Contact me at john.doe@example.com and IBAN BE71 0961 2345 6769."
    hits = detect(text)
    labels = {h["label"] for h in hits}
    assert "EMAIL" in labels
    assert "IBAN" in labels
