# SecurePrompt — Handoff Pack

## Quick start
```bash
bash scripts/setup_venv.sh
source .venv/bin/activate
make ingest-secureprompt
make test-fast
make run-api
```
Then POST to `http://127.0.0.1:8000/scrub` with `{"text":"IBAN BE71 0961 2345 6769","c_level":"C3"}`.
