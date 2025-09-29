# 30_ACCEPTANCE_TESTS

- Golden set from `data/golden/*.jsonl` (built from PROMPTS pairs).
- Metrics: precision/recall per label and overall; target ≥95–98% recall by Milestone-1, ≥99%+ by Milestone-2.
- Perf budgets: <1s per prompt; <10s per image-PDF page (OCR path) on laptop CPU.
- Gates: Do not start next day’s tasks until `pytest -m fast` and the metrics report are updated and passing.
