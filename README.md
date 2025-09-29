# SecurePrompt — Handoff Pack

Open in VS Code, run:
1. `make setup`
2. Drop your external folders into `external/SecurePrompt/DATA` and `external/SecurePrompt/PROMPTS` (or set `EXTERNAL_ROOT`).
3. `make ingest-secureprompt`
4. `make test-fast`
5. `make run-api` and POST to `/scrub`.
