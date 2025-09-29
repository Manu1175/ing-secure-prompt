# 10_TASKS_WEEK1

**Day 1**
- Repo scaffold, CLI skeleton, core detectors (IBAN/PAN/email/phone/name), audit log v1.
- Ingestion: normalize external `DATA/` and `PROMPTS/` → `data/golden/`, `data/eval/`; build `/policy/manifests/`.

**Day 2**
- File loaders (txt/html/csv/pdf), OCR for png; redacted outputs; C-level policy skeleton; de-scrub v1.

**Day 3**
- False-positive controls/validators; selective de-scrub by ID; FastAPI endpoints.

**Day 4**
- Stabilize MVP-3; run evals; export metrics; prepare demo script.
