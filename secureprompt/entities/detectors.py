import re
from typing import List, Dict, Any

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if not digits: return False
    checksum = 0
    parity = (len(digits)-2) % 2
    for i, d in enumerate(digits[:-1]):
        if i % 2 == parity:
            d = d*2
            if d > 9: d -= 9
        checksum += d
    checksum += digits[-1]
    return checksum % 10 == 0

def _iban_ok(s: str) -> bool:
    s = re.sub(r"\s+", "", s).upper()
    if len(s) < 15 or len(s) > 34: return False
    rearranged = s[4:] + s[:4]
    def char_to_int(ch): return str(ord(ch) - 55) if ch.isalpha() else ch
    num = "".join(char_to_int(ch) for ch in rearranged)
    # mod 97 check
    remainder = 0
    for i in range(0, len(num), 7):
        remainder = int(str(remainder) + num[i:i+7]) % 97
    return remainder == 1

PATTERNS = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), lambda m: True, 0.9, "EMAIL_basic"),
    ("PHONE", re.compile(r"\+?\d[\d\s().-]{7,}"), lambda m: True, 0.85, "PHONE_basic"),
    ("PAN",   re.compile(r"\b(?:\d[ -]*?){13,19}\b"), lambda m: _luhn_ok(m.group(0)), 0.95, "PAN_basic"),
    ("IBAN",  re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b"), lambda m: _iban_ok(m.group(0)), 0.95, "IBAN_basic"),
]

def detect(text: str) -> List[Dict[str, Any]]:
    hits = []
    for label, rx, validator, conf, rule_id in PATTERNS:
        for m in rx.finditer(text):
            if validator(m):
                hits.append({"label": label, "start": m.start(), "end": m.end(), "value": m.group(0), "confidence": conf, "rule_id": rule_id})
    # naive name detection could be added later
    return hits
