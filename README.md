# SecurePrompt — Handoff Pack

## Quick start
```bash
bash scripts/setup_venv.sh
source .venv/bin/activate
make ingest-secureprompt
make test-fast
make watch-tests  # optional: keep fast suite running on changes
make metrics
make perf-fast    # optional: quick scrub benchmark
make run-api
curl -s -X POST "http://127.0.0.1:8000/scrub" \
  -H "Content-Type: application/json" \
  -d '{"text":"IBAN BE71 0961 2345 6769","c_level":"C3"}'
```

## Evaluate & Report
- Run `make eval-prompts IN=/mnt/data/merged.xlsx CLEARANCE=C3` to score sanitized prompts/responses from a workbook.
- Generated artifacts land in `reports/`: `<name>_eval.xlsx`, `prompt_eval_summary.json`, and `prompt_eval_anomalies.md` (rows flagged when sanitized output differs from the expected columns).
- Accuracy fields reflect exact text matches; leverage anomalies to inspect diffs and heuristics (e.g., missed `PRODUCT_NAME`).
- Environment knobs: `SP_ENABLE_NER`, `SP_ALLOW_ML_ONLY`, `SP_CLEARANCE` (or filename tags `*_c3_*.xlsx`) influence thresholds via the sensitivity loader.

## Optional ML mode (K2)
- Set `SP_ENABLE_NER=1` to enable optional NER.
- Optional: `SP_NER_MODEL=dslim/bert-base-NER`
- Optional: `SP_CONF_FUSION=max|avg|weighted:0.7` (default `max`)
- Default behaviour is unchanged when ML is off. No model installs unless you explicitly opt in (`pip install -e .[ml]`).
