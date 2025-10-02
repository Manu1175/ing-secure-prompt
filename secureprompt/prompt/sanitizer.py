from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .lexicon import ensure_autolex_from_workbook, load_static_yaml


NUMERIC_REQUIRED = {
    "TRANSFER_ID",
    "PAYMENT_ORDER_ID",
    "AMOUNT",
    "ACCOUNT_BALANCE",
    "NATIONAL_ID",
    "IBAN",
    "DOC_REF",
    "AGREEMENT_ID",
    "VCPU_RAM",
    "STORAGE_GB",
    "GB",
}

ALLOWED_STATUS = {
    "active",
    "inactive",
    "retired",
    "pending",
    "terminated",
    "completed",
    "failed",
    "running",
}


def _ok_replace(token: str, original: str) -> bool:
    if token in NUMERIC_REQUIRED:
        return any(ch.isdigit() for ch in original)
    if token == "STATUS":
        return original.lower() in ALLOWED_STATUS
    return True


_SENT = "\x00PH%05d\x00"
PH_RX = re.compile(r"<[A-Z0-9_]+>")


def _protect_placeholders(text: str) -> Tuple[str, List[str]]:
    slots: List[str] = []

    def _sub(match: re.Match[str]) -> str:
        idx = len(slots)
        slots.append(match.group(0))
        return _SENT % idx

    protected = PH_RX.sub(_sub, text)
    return protected, slots


def _restore_placeholders(text: str, slots: Iterable[str]) -> str:
    restored = text
    for idx, value in reversed(list(enumerate(slots))):
        restored = restored.replace(_SENT % idx, value)
    return restored


@dataclass
class Op:
    label: str
    start: int
    end: int
    original: str
    replacement: str


_HAND_RULE_SPECS: Tuple[Tuple[str, str], ...] = (
    ("CCV", r"\b(cvv|ccv|cvc)\b"),
    ("PIN", r"\bpin\b"),
    ("PASSWORD", r"\b(passcode|password)\b"),
    ("CREDIT_CARD_NUMBER", r"\bcredit\s*card(\s*(number|no\.?|#))?\b"),
    ("EXPIRY_DATE", r"\bexpir(?:y|ation)\s*(date|month|year)?\b"),
    ("RELATIONSHIP_TYPE", r"\brelationship\s*type\b"),
    ("STATUS", r"\b(active|inactive|retired|deprecated)\b"),
    ("CATEGORY", r"\bcategory\b"),
    ("APPROVAL_LEVEL", r"\bapproval\s*level\b"),
    ("DEPARTMENT", r"\bdepartment\b"),
    ("FREQUENCY", r"\b(bi-?annual|quarterly|monthly|weekly|yearly|annually?)\b"),
    ("EMAIL", r"\bemail\b"),
    ("IBAN", r"\biban\b"),
    ("PRODUCT_NAME", r"\b(Current\s+Account|Savings\s+Account|Credit\s*Card|Travel\s+Insurance|Life\s+Insurance|Investment\s+Portfolio|Personal\s+Loan)\b"),
    ("POLICY_NAME", r"\b([A-Z][A-Za-z0-9\-]+(?:\s[A-Z][A-Za-z0-9\-]+){0,6}\sPolicy)\b"),
    ("APPLICATION_NAME", r"\bApp[_\s]?\d{1,4}\b"),
    ("APPLICATION_TYPE", r"\b(application|applications)\b"),
    ("ENVIRONMENT", r"\b(Production|Acceptance|UAT|Development|Dev|Test|Prod)\b"),
    ("PROVIDER", r"\b(AWS|Azure|GCP|Google\s+Cloud|On[- ]?Prem)\b"),
    ("PROCESS_NAME", r"\b([A-Z][A-Za-z0-9\-]+(?:\s[A-Z][A-Za-z0-9\-]+){0,6})\s+process\b"),
    ("AGREEMENT_TYPE", r"\b(supplier|customer|vendor)\s+agreements?\b"),
    ("PAYMENT_TYPE", r"\b(wire|sepa|transfer|direct\s+debit|payment)\b"),
    ("DOCUMENT_TYPE", r"\b(Report|Policy|Guideline|Guidance|Procedure|SOP|Pillar\s*3|Disclosure|Whitepaper)\b"),
    ("GUIDELINE_NAME", r"['“”‘’]?([A-Z][A-Za-z0-9\- ]{2,60})['“”‘’]?\s+guideline"),
    ("TERM", r"['“”‘’]?([A-Za-z0-9\-_]{2,40})['“”‘’]?\s+(term|definition)"),
)

_HAND_RULES: Tuple[Tuple[str, re.Pattern, str], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE), f"<{label}>")
    for label, pattern in _HAND_RULE_SPECS
)

CUSTOMER_NAME_RX = re.compile(r"\b([A-Z][a-z]+(?:\s[A-Z][a-z]+){1,2})(?:’s|'s)?\b", re.IGNORECASE)


def _resolve_hint(xlsx_hint: str | Path | None) -> Optional[str]:
    if not xlsx_hint:
        return None
    try:
        path = Path(xlsx_hint)
    except Exception:
        return str(xlsx_hint)
    if path.is_file():
        return str(path.resolve())
    alt = (Path.cwd() / path).resolve()
    if alt.is_file():
        return str(alt)
    return str(path)


def _fmt(token: str, style: str = "square") -> str:
    return f"[{token}]" if style == "square" else f"<{token}>"


@lru_cache(maxsize=8)
def load_lex_rules(
    xlsx_hint: Optional[str] = None,
    *,
    style: str = "square",
) -> List[Tuple[str, re.Pattern, str]]:
    rules: List[Tuple[str, re.Pattern, str]] = []
    label_to_pattern: dict[str, str] = {}

    static_mapping = load_static_yaml()
    for label, pattern in static_mapping.items():
        label_to_pattern[label] = pattern

    if xlsx_hint:
        try:
            path = Path(xlsx_hint)
        except Exception:
            path = Path(xlsx_hint)
        if path.is_file():
            auto_path, _ = ensure_autolex_from_workbook(path)
            auto_mapping = load_static_yaml(auto_path)
            for label, pattern in auto_mapping.items():
                label_to_pattern[label] = pattern

    for label, pattern in label_to_pattern.items():
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        rules.append((label, compiled, _fmt(label, style)))
    return rules


def _iter_rules(
    xlsx_hint: str | Path | None,
    *,
    style: str = "square",
) -> Iterable[Tuple[str, re.Pattern, str]]:
    hint_key = _resolve_hint(xlsx_hint)
    lex_rules = load_lex_rules(hint_key, style=style)
    seen = {label for label, _, _ in lex_rules}
    for rule in lex_rules:
        yield rule
    for label, pattern, replacement in _HAND_RULES:
        if label in seen:
            continue
        yield label, pattern, _fmt(label, style)


def sanitize_prompt(
    text: str,
    xlsx_hint: str | Path | None = None,
    *,
    style: str = "square",
):
    ops: List[Op] = []
    s, slots = _protect_placeholders(text)

    for label, pat, replacement in _iter_rules(xlsx_hint, style=style):
        def _cb(match, label=label, replacement=replacement):
            nonlocal s, ops
            start, end = match.start(), match.end()
            original = s[start:end]
            if not _ok_replace(label, original):
                return original
            ops.append(Op(label, start, end, original, replacement))
            return replacement

        s = pat.sub(_cb, s)

    def _name_cb(match):
        nonlocal s, ops
        start, end = match.start(), match.end()
        original = s[start:end]
        if "<" in original or "Policy" in original or "Account" in original:
            return original
        replacement = _fmt("CUSTOMER_NAME", style)
        ops.append(Op("CUSTOMER_NAME", start, end, original, replacement))
        return replacement

    s = CUSTOMER_NAME_RX.sub(_name_cb, s)
    s = _restore_placeholders(s, slots)
    plain = re.sub(r"<[A-Z0-9_]+>", "", s)
    if len(plain.strip()) < max(10, int(0.4 * len(text))):
        s = text
        ops.clear()
    return s, ops


def descrub(text: str, ops: List[Op]) -> str:
    s = text
    for op in sorted(ops, key=lambda o: o.start, reverse=True):
        s = s[:op.start] + op.original + s[op.end:]
    return s


__all__ = ["Op", "sanitize_prompt", "descrub", "load_lex_rules"]
