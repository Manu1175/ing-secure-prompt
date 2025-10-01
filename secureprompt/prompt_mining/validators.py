
from __future__ import annotations
import re

PAN_IN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")  # India PAN (AAAAA9999A)

def _digits(s: str) -> str:
    return re.sub(r"[^0-9]", "", s)

def luhn_ok(num: str) -> bool:
    n = _digits(num)
    if not (12 <= len(n) <= 19):
        return False
    s, alt = 0, False
    for ch in n[::-1]:
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d
        alt = not alt
    return (s % 10) == 0

def is_card_pan(sample: str) -> bool:
    return luhn_ok(sample)

def is_india_pan(sample: str) -> bool:
    return bool(PAN_IN_RE.search(sample))

def classify_pan(sample: str) -> str | None:
    if is_card_pan(sample):
        return "CARD_PAN"
    if is_india_pan(sample):
        return "IN_PAN"
    return None
