from __future__ import annotations
import re
import hashlib
from typing import List, Dict, Tuple, Iterable

def _luhn_ok(number: str) -> bool:
    digits = [int(ch) for ch in number if ch.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for idx, value in enumerate(digits[:-1]):
        if idx % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        checksum += value
    checksum += digits[-1]
    return checksum % 10 == 0

def _sha10(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:10]

def _ident(clevel: str, label: str, value: str) -> str:
    return f"{clevel}::{label}::{_sha10(value)}"

def _entity(
    *,
    label: str,
    span: Tuple[int, int],
    detector: str,
    value: str,
    clevel: str,
    action: str,
    conf: float,
    mask_preview: str = "***",
    reason: str | None = None,
) -> Dict:
    s, e = span
    return {
        # positions (compatible with pipeline/xlsx)
        "start": s,
        "end": e,
        # also keep the old 'span' list for new code paths
        "span": [s, e],
        # semantics
        "label": label,
        "detector": detector,
        "rule_id": detector,
        "confidence": conf,
        "confidence_sources": {"rule": conf},
        "c_level": clevel,
        "identifier": _ident(clevel, label, value),
        "action": action,
        "explanation": reason or f"rule {label} ({detector}; base {conf})",
        "mask_preview": mask_preview,
        "value": value,
    }

def _overlaps(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    return not (a[1] <= b[0] or b[1] <= a[0])

def _free(span: Tuple[int,int], taken: List[Tuple[int,int]]) -> bool:
    return all(not _overlaps(span, t) for t in taken)

def _append_non_overlapping(out: List[Dict], ents: Iterable[Dict], taken: List[Tuple[int,int]]):
    for e in ents:
        s, e_ = e["start"], e["end"]
        if _free((s, e_), taken):
            out.append(e)
            taken.append((s, e_))

# ---------- Regexes ----------
IBAN_RX = re.compile(
    r"\b(?:IBAN\s*)?([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{3,4}){2,7})\b",
    re.IGNORECASE,
)

BIC_RX = re.compile(
    r"\b(?:BIC[:\s]*)?([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"
)

EMAIL_RX = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,24}\b"
)

DOB_CTX_RX = re.compile(
    r"\b(?:DOB|[Bb]irth(?:\s*date)?|born(?:\s*on)?)[:\s]+"
    r"(?P<date>(?:\d{4}-\d{2}-\d{2}|\d{2}[\/\-]\d{2}[\/\-]\d{4}))\b"
)

DATE_RX = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}[\/\-\.]\d{2}[\/\-\.]\d{4})\b"
)

YEAR_RX = re.compile(r"\b(19\d{2}|20\d{2})\b")

CODES = r"EUR|USD|GBP|CHF|JPY|AUD|CAD|CNY|INR|SEK|NOK|DKK|PLN|HUF|CZK|RON|TRY|RUB|ZAR|NZD|MXN|BRL|SGD|HKD"
SYM = r"€|\$|£|¥"

CUR_AMT_RX1 = re.compile(
    rf"\b(?P<cur>(?:{SYM}|{CODES}))\s*(?P<amt>\d{{1,3}}(?:[ ,]\d{{3}})*(?:[.,]\d{{2}})?|\d+(?:[.,]\d{{2}})?)\b",
    re.IGNORECASE,
)
CUR_AMT_RX2 = re.compile(
    rf"\b(?P<amt>\d{{1,3}}(?:[ ,]\d{{3}})*(?:[.,]\d{{2}})?|\d+(?:[.,]\d{{2}})?)\s*(?P<cur>(?:{SYM}|{CODES}))\b",
    re.IGNORECASE,
)

PAN_RX = re.compile(
    r"\b(?:\d[ -]?){13,19}\d\b"
)

# Guard phones from IBAN-like sequences via lookbehinds around "IBAN " or country/BBAN prefix
PHONE_RX = re.compile(
    r"""(?ix)
    (?<!IBAN\ )        # don't grab right after 'IBAN '
    (?<![A-Z]{2}\d{2}\ ) # or country+check (e.g., BE47 )
    \b(?:\+?\d[\d\-\s().]{6,18}\d)\b
    """
)

STATUS_WORDS = (
    "approved|declined|pending|failed|successful|success|canceled|cancelled|"
    "completed|processing|scheduled|rejected|verified|denied|refunded"
)
STATUS_RX = re.compile(rf"\b(?P<status>{STATUS_WORDS})\b", re.IGNORECASE)

XFER_RX = re.compile(
    r"\b(?:TX|TRX|TID|Transfer(?:\s*ID)?)[:=\s\-]*([A-Za-z0-9][A-Za-z0-9\-_.]{4,36})\b",
    re.IGNORECASE,
)

# A simple capitalized bigram as NAME (Jane Doe)
NAME_RX = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b"
)

def _find_matches(text: str, rx: re.Pattern) -> Iterable[re.Match]:
    return rx.finditer(text)

def _pass_iban(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, IBAN_RX):
        s,e = m.span()
        val = m.group(1).strip()
        ents.append(_entity(
            label="IBAN", span=(s,e), detector="IBAN_generic", value=val,
            clevel="C3", action="redact", conf=0.99, mask_preview="██"
        ))
    return ents

def _pass_bic(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, BIC_RX):
        s,e = m.span()
        val = m.group(1).strip()
        if not re.match(r"^[A-Z]{4}[A-Z]{2}", val):
            continue
        ents.append(_entity(
            label="BIC", span=(s,e), detector="BIC_swift", value=val,
            clevel="C3", action="redact", conf=0.97, mask_preview="██"
        ))
    return ents

def _pass_email(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, EMAIL_RX):
        s,e = m.span()
        val = m.group(0)
        ents.append(_entity(
            label="EMAIL", span=(s,e), detector="EMAIL_simple", value=val,
            clevel="C4", action="mask", conf=0.98
        ))
    return ents

def _pass_dob(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, DOB_CTX_RX):
        s,e = m.span("date")
        val = m.group("date")
        ents.append(_entity(
            label="DOB", span=(s,e), detector="DOB_ctx", value=val,
            clevel="C3", action="redact", conf=0.96, mask_preview="██"
        ))
    return ents

def _pass_date(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, DATE_RX):
        s,e = m.span()
        val = m.group(0)
        ents.append(_entity(
            label="DATE", span=(s,e), detector="DATE_generic", value=val,
            clevel="C3", action="mask", conf=0.94
        ))
    return ents

def _pass_year(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, YEAR_RX):
        s,e = m.span()
        val = m.group(0)
        ents.append(_entity(
            label="YEAR", span=(s,e), detector="YEAR_1900_2099", value=val,
            clevel="C3", action="mask", conf=0.92
        ))
    return ents

def _emit_amount_currency(text: str, amt_s: int, amt_e: int, amt_val: str,
                          cur_s: int, cur_e: int, cur_val: str,
                          taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    if _free((cur_s, cur_e), taken):
        ents.append(_entity(
            label="CURRENCY", span=(cur_s, cur_e), detector="CUR_code_or_symbol", value=cur_val,
            clevel="C3", action="mask", conf=0.96
        ))
    if _free((amt_s, amt_e), taken):
        ents.append(_entity(
            label="AMOUNT", span=(amt_s, amt_e), detector="AMOUNT_near_currency", value=amt_val,
            clevel="C3", action="mask", conf=0.96
        ))
    return ents

def _pass_amount_currency(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, CUR_AMT_RX1):
        cur = m.group("cur")
        amt = m.group("amt")
        cur_s, cur_e = m.span("cur")
        amt_s, amt_e = m.span("amt")
        ents.extend(_emit_amount_currency(text, amt_s, amt_e, amt, cur_s, cur_e, cur, taken))
    for m in _find_matches(text, CUR_AMT_RX2):
        cur = m.group("cur")
        amt = m.group("amt")
        cur_s, cur_e = m.span("cur")
        amt_s, amt_e = m.span("amt")
        ents.extend(_emit_amount_currency(text, amt_s, amt_e, amt, cur_s, cur_e, cur, taken))
    return ents


def _clean_pan(value: str) -> str:
    return re.sub(r"\D", "", value)


def _pass_pan(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, PAN_RX):
        s, e = m.span()
        raw = m.group(0)
        digits = _clean_pan(raw)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if not _luhn_ok(digits):
            continue
        if _free((s,e), taken):
            ents.append(_entity(
                label="PAN", span=(s,e), detector="PAN_luhn", value=raw,
                clevel="C4", action="redact", conf=0.98, mask_preview="██"
            ))
    return ents

def _pass_status(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, STATUS_RX):
        s,e = m.span("status")
        val = m.group("status")
        ents.append(_entity(
            label="STATUS", span=(s,e), detector="STATUS_words", value=val,
            clevel="C2", action="mask", conf=0.90
        ))
    return ents

def _pass_transfer_id(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, XFER_RX):
        s,e = m.span(1)
        val = m.group(1)
        ents.append(_entity(
            label="TRANSFER_ID", span=(s,e), detector="XFER_id_like", value=val,
            clevel="C3", action="redact", conf=0.95, mask_preview="██"
        ))
    return ents

def _pass_phone(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, PHONE_RX):
        s,e = m.span()
        val = m.group(0)
        ents.append(_entity(
            label="PHONE", span=(s,e), detector="PHONE_e164ish", value=val,
            clevel="C4", action="mask", conf=0.97
        ))
    return ents

def _pass_name(text: str, taken: List[Tuple[int,int]]) -> List[Dict]:
    ents=[]
    for m in _find_matches(text, NAME_RX):
        s,e = m.span()
        val = m.group(1)
        if any(val.startswith(pfx) for pfx in ("Transfer", "Invoice", "Order", "Bank", "Account")):
            continue
        ents.append(_entity(
            label="NAME", span=(s,e), detector="NAME_capitalized_bigram", value=val,
            clevel="C2", action="mask", conf=0.93
        ))
    return ents

def detect(text: str, clearance: str = "C3") -> List[Dict]:
    if not text:
        return []

    entities: List[Dict] = []
    taken: List[Tuple[int,int]] = []

    _append_non_overlapping(entities, _pass_iban(text, taken), taken)
    _append_non_overlapping(entities, _pass_bic(text, taken), taken)
    _append_non_overlapping(entities, _pass_email(text, taken), taken)
    _append_non_overlapping(entities, _pass_dob(text, taken), taken)
    _append_non_overlapping(entities, _pass_date(text, taken), taken)
    _append_non_overlapping(entities, _pass_year(text, taken), taken)
    _append_non_overlapping(entities, _pass_amount_currency(text, taken), taken)
    _append_non_overlapping(entities, _pass_pan(text, taken), taken)
    _append_non_overlapping(entities, _pass_status(text, taken), taken)
    _append_non_overlapping(entities, _pass_transfer_id(text, taken), taken)
    _append_non_overlapping(entities, _pass_phone(text, taken), taken)
    _append_non_overlapping(entities, _pass_name(text, taken), taken)

    entities.sort(key=lambda d: (d["start"], d["end"], d["label"]))
    return entities
