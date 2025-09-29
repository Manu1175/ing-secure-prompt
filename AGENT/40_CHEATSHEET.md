# 40_CHEATSHEET

**Make targets**: `make setup | ingest-secureprompt | lint | test | test-fast | perf | run-cli | run-api | demo-data`
**Commands**: `pytest -q`, `ruff check`, `black --check`, `mypy --strict`, `python -m secureprompt.cli`
**Data**: `/data/golden/` (truth), `/data/eval/` (samples), `/data/out/` (scrubbed)
**VS Code tasks**: map `test-fast`, `run-api`, `demo` to keybindings
