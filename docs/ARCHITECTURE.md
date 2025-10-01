# SecurePrompt Architecture

## High-level flow

1. **Ingestion** – Text and workbook uploads reach the API via `/scrub`, `/files/redact-text`, or the web UI. Xlsx files are parsed cell-by-cell (`secureprompt/files/xlsx.py`), while free text is handled directly.
2. **Detection pipeline** – The scrub pipeline (`secureprompt/scrub/pipeline.py`) applies regex/policy detectors and optional NER fusion to identify sensitive spans. Each entity receives a deterministic identifier and confidence metadata.
3. **Selective sanitisation** – `secureprompt/ui/selective.py` masks or retains placeholders according to the caller’s clearance. Excel cells are rewritten with their placeholders and tracked alongside sheet/cell offsets.
4. **Receipt storage** – Every scrub operation creates an encrypted receipt (`secureprompt/receipts/store.py`) capturing original/scrubbed hashes, entity metadata (including Excel coordinates), and the placeholder map. Receipts live under `data/receipts/<operation_id>.json`.
5. **Audit logging** – The v2 logger (`secureprompt/audit/log.py`) appends JSONL events and mirrors them into SQLite. Each event stores hash-chain fields, per-label/per-clearance counts, hashes, receipt references, and basic actor/client info. UI actions (`/ui/scrub`, `/descrub`) emit corresponding entries.
6. **Descrub** – `/descrub` loads receipts, enforces role/clearance gates, and selectively restores identifiers using the encrypted originals (`secureprompt/receipts/descrub.py`).

## Baseline scoring

Offline mining (`secureprompt/prompt_mining/baseline.py`, `tools/make_baseline.py`) scans PROMPTS workbooks to establish label/C-level expectations. At run time `secureprompt/ui/scoring.py` compares achieved counts with clearance-filtered expected counts, yielding the score card on the dashboard.

## User interface

The dashboard template (`templates/dashboard.html`) consolidates classification summary, entity table, receipt metadata, download links for redacted artefacts (`/redacted/<operation_id>/...`), and optional baseline score comparison. `/audit` visualises recent events with chain hashes and links to the stored receipts; `/audit/jsonl` exposes the raw log.

## Performance harness

`tools/perf_fast.py` benchmarks text and spreadsheet scrubbing end-to-end, printing ops/sec and latency figures to assist manual performance validation.

