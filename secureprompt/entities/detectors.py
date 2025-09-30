\
import re, os, yaml, datetime as dt
from typing import List, Dict, Any, Tuple

def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", s)]
    if len(digits) < 13: return False
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
    remainder = 0
    for i in range(0, len(num), 7):
        remainder = int(str(remainder) + num[i:i+7]) % 97
    return remainder == 1

def _be_nrn_ok(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    if len(digits) != 11: return False
    base = int(digits[:9]); cc = int(digits[9:])
    if (97 - (base % 97)) == cc: return True
    if (97 - (int("2"+digits[:9]) % 97)) == cc: return True
    return False

def _date_like_ok(s: str) -> bool:
    s = s.replace("/", "-")
    for fmt in ("%Y-%m-%d","%d-%m-%Y"):
        try:
            dt.datetime.strptime(s, fmt); return True
        except Exception:
            pass
    return False

VALIDATORS = {
    "none": lambda m: True,
    "luhn": lambda m: _luhn_ok(m.group(0)),
    "iban_checksum": lambda m: _iban_ok(m.group(0)),
    "be_nrn": lambda m: _be_nrn_ok(m.group(0)),
    "date": lambda m: _date_like_ok(m.group(0)),
}

def _compile_from_manifests(paths: List[str]):
    patterns = []
    for p in paths:
        if not os.path.exists(p): continue
        with open(p, "r") as f:
            rules = yaml.safe_load(f) or []
        for r in rules:
            try:
                label = r["label"].upper()
                rx = re.compile(r["pattern"])
                validator = r.get("validator","none")
                conf = float(r.get("confidence", 0.8))
                rule_id = r.get("id", f"{label}_rule")
                patterns.append((label, rx, validator, conf, rule_id))
            except Exception:
                continue
    return patterns

def load_patterns():
    base = os.environ.get("SECUREPROMPT_POLICY_DIR", "policy/manifests")
    return _compile_from_manifests([
        os.path.join(base, "c2.yml"),
        os.path.join(base, "c3.yml"),
        os.path.join(base, "c4.yml"),
    ])

PATTERNS = load_patterns()

def detect(text: str) -> List[Dict[str, Any]]:
    hits = []
    for label, rx, validator_key, conf, rule_id in PATTERNS:
        for m in rx.finditer(text):
            validator = VALIDATORS.get(validator_key, VALIDATORS["none"])
            if validator(m):
                hits.append({"label": label, "start": m.start(), "end": m.end(), "value": m.group(0), "confidence": conf, "rule_id": rule_id})
    return hits
