from api.main import _combine_and_tokenize


def test_overlay_on_raw_avoids_shift():
    raw = (
        "Send €3,250 on 14/09/2024 to IBAN BE71 0961 2345 6769; "
        "confirm to sara.janssens@ing.com or +32 475 59 64 94. "
        "Publish newsroom item: Annual Report 2024 -> https://newsroom.ing.be/annual-report-2024"
    )
    email = "sara.janssens@ing.com"
    iban = "IBAN BE71 0961 2345 6769"
    phone = "+32 475 59 64 94"
    email_s = raw.index(email)
    email_e = email_s + len(email)
    iban_s = raw.index(iban)
    iban_e = iban_s + len(iban)
    phone_s = raw.index(phone)
    phone_e = phone_s + len(phone)
    entities = [
        {"label": "EMAIL", "start": email_s, "end": email_e},
        {"label": "IBAN", "start": iban_s, "end": iban_e},
        {"label": "PHONE", "start": phone_s, "end": phone_e},
    ]
    out = _combine_and_tokenize(raw, entities)
    assert "<EMAIL>" in out and "<PHONE>" in out and "<IBAN>" in out
    assert "<DOCUMENT_TYPE>" in out and "<YEAR>" in out and "<LINK>" in out
