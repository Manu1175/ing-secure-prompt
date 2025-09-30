setup:
	python -m pip install -U pip
	pip install -r requirements.txt

ingest-secureprompt:
	python tools/ingest_secureprompt_repo.py --config config/datasets.yml

slides:
	python tools/make_onepager_pptx.py

lint:
	ruff check . && black --check . && mypy --strict secureprompt

test:
	pytest -q

test-fast:
	pytest -q -k "ingest or entities or scrub or image_redaction or pdf_text"

run-cli:
	python -m secureprompt.cli scrub README.md || true

run-api:
	uvicorn api.main:app --reload

perf:
	python -c "print('perf placeholder')"
