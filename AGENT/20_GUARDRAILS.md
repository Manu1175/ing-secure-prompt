# 20_GUARDRAILS

## Entity labels (initial)
IBAN, PAN (card), EMAIL, PHONE, NAME, ADDRESS, ACCOUNT_ID, NATIONAL_ID.

## Identifier scheme
`C{level}::{label}::{sha256(salt+value)[:10]}` — salt from env var; never store plaintext in logs.

## Explainability per match
```json
{ "label": "IBAN", "span": [start, end], "detector": "regex+checksum", "confidence": 0.95, "rule_id": "IBAN_basic", "c_level": "C4" }
```

## Policies
- Load from `/policy/manifests/{c2,c3,c4}.yml`.
- Per-label toggles and default actions: C2 mask or redact; C3/C4 redact.

## Audit schema (append-only)
`ts, actor, session_id, original_hash, scrubbed_hash, actions[], entities[], confidences[], justification?, prev_hash, curr_hash`.

## De-scrub
Role-gated; full or selective by ID; justification required; all attempts logged.
