# 25_DATA_INTEGRATION — Using external DATA/ and PROMPTS/

**Source of truth:** two external folders will exist under the repo:
- `external/SecurePrompt/DATA/**`
- `external/SecurePrompt/PROMPTS/**`

**What’s inside (observed):**
- PROMPTS/ sheets include: **Prompt/Original Prompt, Sanitized Prompt, Response, Sanitized Response**.
- DATA/ includes banking-like tables (customers, payments, auth), plus IBAN transfer orders and policy/guideline sheets.

**Canonical record schema (normalized to JSONL):**
```yaml
id: str                       # stable id (filename or sheetname:row)
source_path: str              # original file
modality: text|pdf|image|csv  # how to process
c_level: C2|C3|C4|null        # if provided
raw_text: str|null            # text payload for text/txt/csv/jsonl
file_bytes_b64: str|null      # for pdf/image in tests if needed
expected_scrub: str|null      # gold scrubbed text (when provided in PROMPTS/)
entities:                     # optional gold spans
  - {label: IBAN|PAN|EMAIL|..., start: int, end: int, c_level: C*}
notes: str|null
```

**Header heuristics (case/underscore/locale insensitive):**
- `prompt|original prompt|text|input` → `raw_text`
- `sanitized prompt|sanitized` → `expected_scrub`
- `response` / `sanitized response` are kept for optional secondary tasks
- `c|class|confidentiality|level|c_level` → `c_level`
- `entities|labels|spans|annotations` → `entities`

**Policy manifests from DATA/**
If spreadsheets with columns like `pattern|regex|validator|label|action` exist, convert to `/policy/manifests/{c2,c3,c4}.yml`. Otherwise create initial manifests with standard detectors and default actions by C-level.

**Workflow Codex must follow:**
1) Run `make ingest-secureprompt` → produces `data/golden/*.jsonl`, `data/eval/*.jsonl`, and `/policy/manifests/*.yml`.
2) Unit tests read only from normalized JSONL (not raw spreadsheets).
3) Evaluations compute precision/recall on `data/golden/` (PROMPTS pairs).
4) The scrubbing pipeline loads `/policy/manifests/*.yml` on startup.
