# Metrics

| label | n | residual_hits | replaced | exact_matches | recall | notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| unknown | 400 | 0 | 2168 | 1 | 0.000 | no sensitive entities |
| overall | 400 | 0 | 2168 | 1 | 0.000 | no sensitive entities |


_Note_: Excel (.xlsx) uploads are now scrubbed cell-by-cell; redacted workbooks replace
detected values with their deterministic placeholders while receipts capture the originating
sheet/cell offsets.

## Baseline & Score

PROMPTS/*.xlsx are mined offline to build `reports/baseline_counts.json` / `.csv`. The baseline
tracks placeholder label counts and associated C-levels per workbook. When a user uploads a
workbook via the UI, the classification summary shows the masked entities, and the score card
compares achieved counts with the expected baseline at the selected clearance. Only placeholders
that must be hidden for that clearance (entity.c_level strictly greater than the clearance) are
considered. Per-label precision = min(expected, achieved) / expected, averaged to produce a
percentage score; missing/extra counts are displayed for demo KPIs.
