from secureprompt.entities.detectors import detect

def labels(s):
    return {e["label"] for e in detect(s)}

def test_bank_fields_and_phone_do_not_collide():
    s = "Send 500 EUR to IBAN BE47 1234 5678 9012; BIC GEBABEBB; call +32 2 555 12 34; TX-9A8B6C"
    L = labels(s)
    assert "IBAN" in L
    assert "BIC" in L
    assert "AMOUNT" in L and "CURRENCY" in L
    assert "PHONE" in L
    assert "TRANSFER_ID" in L

def test_dates_and_dob_context():
    s = "DOB: 1990-05-12; invoice date 12/10/2024; year 2025"
    L = labels(s)
    assert "DOB" in L
    assert "DATE" in L
    assert "YEAR" in L

def test_name_status():
    s = "Status: approved by Jane Doe"
    L = labels(s)
    assert "STATUS" in L
    assert "NAME" in L
