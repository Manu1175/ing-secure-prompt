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
