# 40_CHEATSHEET

**Make**: `setup | ingest-secureprompt | lint | test | test-fast | perf | run-cli | run-api | slides`  
**Run**: `pytest -q`, `ruff check`, `black --check`, `mypy --strict`, `python -m secureprompt.cli`  
**Data**: `/data/golden/` (truth), `/data/eval/` (samples), `/data/out/` (scrubbed)  
**VS Code**: `.vscode/tasks.json` has `test-fast`, `run-api`, `ingest`
