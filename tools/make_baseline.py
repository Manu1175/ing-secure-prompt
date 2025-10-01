"""Generate baseline placeholder counts from PROMPTS workbooks."""

from __future__ import annotations

import argparse
from pathlib import Path

from secureprompt.prompt_mining import baseline


def main() -> None:
    parser = argparse.ArgumentParser(description="Build baseline counts from PROMPTS")
    parser.add_argument("folder", nargs="?", default="PROMPTS", help="Folder with *.xlsx prompts")
    parser.add_argument("--placeholders", default="policy/placeholders.yml")
    parser.add_argument("--out-json", default="reports/baseline_counts.json")
    parser.add_argument("--out-csv", default="reports/baseline_counts.csv")
    args = parser.parse_args()

    prompts_dir = Path(args.folder)
    placeholders_path = Path(args.placeholders)
    baseline_data = baseline.build_baseline(
        str(prompts_dir), placeholders_path=placeholders_path
    )

    json_path = Path(args.out_json)
    csv_path = Path(args.out_csv)

    baseline.write_json(json_path, baseline_data)
    rows = baseline.flatten_counts(baseline_data)
    baseline.write_csv(csv_path, rows)

    total_files = baseline_data.get("total_files", 0)
    total_labels = sum(baseline_data.get("global", {}).get("by_label", {}).values())
    print(f"Baseline built from {total_files} files; total placeholders: {total_labels}")
    print(f"JSON -> {json_path}")
    print(f"CSV  -> {csv_path}")


if __name__ == "__main__":
    main()

