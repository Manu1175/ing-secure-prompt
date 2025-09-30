SHELL := /bin/bash

.PHONY: help setup dev-install ingest-secureprompt slides lint format typecheck test test-fast run-cli run-api clean env check watch-tests

help:
	@echo "setup | dev-install | ingest-secureprompt | test-fast | test | lint | format | typecheck | run-cli | run-api | slides | env | clean | check | watch-tests"

setup:
	python -m pip install -U pip
	pip install -r requirements.txt
	pip install -e .

dev-install:
	pip install -e .

ingest-secureprompt:
	python tools/ingest_secureprompt_repo.py --config config/datasets.yml

slides:
	python tools/make_onepager_pptx.py

lint:
	ruff check .
	black --check .
	mypy --strict secureprompt

format:
	black .

typecheck:
	mypy --strict secureprompt

test:
	pytest -q

test-fast:
	pytest -q -k "ingest or entities or scrub or image_redaction or pdf_text"

run-cli:
	python -m secureprompt.cli scrub README.md || true

run-api:
	uvicorn api.main:app --reload

env:
	python -c "import sys; print('python:', sys.version)"

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .mypy_cache .pytest_cache .ruff_cache
	rm -rf data/golden data/eval data/out
	rm -f slides/OnePager.pptx

check:
	make lint
	make test-fast

# Auto test watcher: re-runs pytest whenever files change
watch-tests:
	ptw --onfail "echo FAIL" --onpass "echo PASS" -c
	
metrics:
	@PYTHONPATH=. python tools/regenerate_metrics.py

metrics-open: metrics
	@echo "Opening reports/metrics.md…"
	@/usr/bin/open reports/metrics.md 2>/dev/null || true
