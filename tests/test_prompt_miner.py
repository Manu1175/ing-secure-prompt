from __future__ import annotations

from pathlib import Path

import pandas as pd

from secureprompt.prompt_mining.miner import mine_prompts, write_placeholders_yaml


def test_mine_prompts_extracts_placeholders(tmp_path: Path) -> None:
    df = pd.DataFrame(
        {
            "Original Prompt": ["Email john@bank.com"],
            "Sanitized Prompt": ["Email <CUSTOMER_EMAIL>"],
        }
    )
    excel_path = tmp_path / "sample.xlsx"
    df.to_excel(excel_path, index=False)

    results = mine_prompts(tmp_path)

    assert "EMAIL" in results
    email_entry = results["EMAIL"]
    assert "<CUSTOMER_EMAIL>" in email_entry["templates"]
    assert any(example.startswith("john@") for example in email_entry["examples"])
    assert email_entry["c_level"] == "C3"


def test_write_placeholders_yaml(tmp_path: Path) -> None:
    data = {
        "EMAIL": {
            "c_level": "C3",
            "templates": ["<CUSTOMER_EMAIL>"],
            "examples": ["john@bank.com"],
        }
    }
    output = write_placeholders_yaml(data, path=tmp_path / "placeholders.yml")
    content = output.read_text(encoding="utf-8")

    assert "EMAIL" in content
    assert "c_level" in content
