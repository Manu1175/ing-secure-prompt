# ===== SecurePrompt Makefile =====

PYTHON      := python
UVICORN     := uvicorn
APP         := api.main:app
PORT        ?= 8000
RELOAD      ?= --reload

.PHONY: help
help:
	@echo "Targets:"
	@echo "  dev           - Kill port $(PORT) if busy and start uvicorn on $(PORT)"
	@echo "  dev-free      - Start uvicorn on the next free port starting at $(PORT)"
	@echo "  test-fast     - Run focused test subset with repo on PYTHONPATH"
	@echo "  watch-tests   - (optional) pytest watcher if you use ptw"
	@echo "  metrics-open  - Generate metrics report (if script present)"
	@echo "  db-init       - No-op placeholder (UI has no DB)"
	@echo "  make-baseline - Generate PROMPTS baseline counts"
	@echo "  release       - Build dist/secureprompt_handoff_v3.zip"
	@echo "  clean         - Remove build artifacts"

.PHONY: test-fast
test-fast:
	PYTHONPATH=$(shell pwd):$$PYTHONPATH pytest -q -k "ingest or entities or scrub or image_redaction or pdf_text or xlsx or audit or scoring"

.PHONY: watch-tests
watch-tests:
	@which ptw >/dev/null 2>&1 || { echo "Install ptw (pytest-watch) to use watch-tests"; exit 1; }
	PYTHONPATH=$(shell pwd):$$PYTHONPATH ptw -q


.PHONY: dev
dev:
	- PID=$$(lsof -nP -iTCP:8000 -sTCP:LISTEN -t) ; [ -n "$$PID" ] && kill -TERM $$PID || true
	sleep 1
	- PID=$$(lsof -nP -iTCP:8000 -sTCP:LISTEN -t) ; [ -n "$$PID" ] && kill -KILL $$PID || true
	uvicorn api.main:app --reload --port 8000

.PHONY: dev-free
dev-free:
	@PORT=8000; \
	while lsof -nP -iTCP:$$PORT -sTCP:LISTEN -t >/dev/null 2>&1; do PORT=$$((PORT+1)); done; \
	echo "Using port $$PORT"; \
	uvicorn api.main:app --reload --port $$PORT

.PHONY: metrics-open
metrics-open:
	@if [ -f tools/regenerate_metrics.py ]; then \
		PYTHONPATH=. $(PYTHON) tools/regenerate_metrics.py ; \
	else \
		echo "TBD: metrics script not found; create secureprompt/eval/metrics.py"; \
	fi

.PHONY: db-init
db-init:
	@echo "No DB init required for UI without auth"

.PHONY: release
release:
	mkdir -p dist
	zip -r dist/secureprompt_handoff_v3.zip \
		AGENT policy secureprompt api tests Makefile pyproject.toml README.md \
		-x "__pycache__/*" -x "*.pyc" -x ".venv/*" -x "dist/*"
	@echo "Built dist/secureprompt_handoff_v3.zip"

.PHONY: mine-placeholders
mine-placeholders:
	$(PYTHON) tools/mine_placeholders.py
	@echo "Placeholders written to policy/placeholders.yml"

.PHONY: make-baseline
make-baseline:
	$(PYTHON) tools/make_baseline.py

.PHONY: keys-dev
keys-dev:
	@echo "Fernet key path: data/keys/fernet.key"
	@test -f data/keys/fernet.key || { echo "No key yet; it will be created on first run."; true; }

.PHONY: clean
clean:
	rm -rf build dist *.egg-info .pytest_cache __pycache__ */__pycache__ .mypy_cache
