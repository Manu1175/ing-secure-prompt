# 25_DATA_INTEGRATION — Using external DATA/ and PROMPTS/

**Source of truth:**
- `external/SecurePrompt/DATA/**`
- `external/SecurePrompt/PROMPTS/**`

**Canonical JSONL schema:**
```yaml
id: str
source_path: str
modality: text|pdf|image|csv
c_level: C2|C3|C4|null
raw_text: str|null
file_bytes_b64: str|null
expected_scrub: str|null
entities: [ {label,start,end,c_level}? ]
notes: str|null
```

**Header heuristics (case/underscore/locale insensitive):**
- `prompt|original prompt|text|input` → `raw_text`
- `sanitized prompt|sanitized` → `expected_scrub`
- `response` / `sanitized response` retained for optional secondary tasks
- `c|class|confidentiality|level|c_level` → `c_level`
- `entities|labels|spans|annotations` → `entities`

**Workflow:**
1) `make ingest-secureprompt` → emits `data/golden/*.jsonl`, `data/eval/eval.jsonl`, `policy/manifests/*.yml`.
2) Unit tests read only normalized JSONL.
3) Evaluations compute precision/recall on `data/golden/`.
4) Scrubber loads `/policy/manifests/*.yml` at startup.
