"""CLI entry point to mine placeholder templates from prompt spreadsheets."""

from __future__ import annotations

import argparse
from pathlib import Path

from secureprompt.prompt_mining import mine_prompts, write_placeholders_yaml


def main() -> None:
    parser = argparse.ArgumentParser(description="Mine placeholder templates from PROMPTS")
    parser.add_argument("folder", nargs="?", default="PROMPTS", help="Folder containing .xlsx prompts")
    parser.add_argument("--output", default="policy/placeholders.yml", help="Output YAML path")
    parser.add_argument("--limit", type=int, default=5, help="Rows to display in summary output")
    args = parser.parse_args()

    data = mine_prompts(args.folder)
    path = write_placeholders_yaml(data, path=args.output)

    print(f"Wrote placeholder catalogue to {path}")
    print("")
    print(f"Summary (top {args.limit} entries):")
    for label, info in list(data.items())[: args.limit]:
        templates = ", ".join(info.get("templates", [])[:3])
        examples = ", ".join(info.get("examples", [])[:1])
        print(f"- {label}: c_level={info.get('c_level')} templates=[{templates}] examples=[{examples}]")


if __name__ == "__main__":
    main()

