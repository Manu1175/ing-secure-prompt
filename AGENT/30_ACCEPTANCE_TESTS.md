# 30_ACCEPTANCE_TESTS

- Metrics: precision/recall per label & overall; target ≥95–98% recall by Milestone-1, ≥99%+ by Milestone-2.
- Perf budgets: <1s per prompt; <10s per OCR page on laptop CPU.
- Gates: do not move to next day until `pytest -m fast` passes and `/reports/metrics.md` is updated.
