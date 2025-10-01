
from pathlib import Path
import yaml
from tools.clean_placeholders import main as run_clean

def test_pan_examples_cleaned(tmp_path, monkeypatch):
    p = tmp_path/"policy"; p.mkdir()
    f = p/"placeholders.yml"
    bogus = [
        {"label":"PAN","c_level":"C4","examples":["2023 ING Belgium"]},
        {"label":"PAN","c_level":"C4","examples":["4539 3195 0343 6467"]},
        {"label":"PAN","c_level":"C4","examples":["ABCDE1234F"]},
    ]
    f.write_text(yaml.safe_dump(bogus, sort_keys=False))

    import tools.clean_placeholders as mod
    mod.IN_PATH = f
    mod.OUT_PATH = f
    assert run_clean() == 0

    out = yaml.safe_load(f.read_text())
    labels = [e["label"] for e in out]
    assert "CARD_PAN" in labels and "IN_PAN" in labels
    for e in out:
        if e["label"] in ("CARD_PAN","IN_PAN"):
            assert e["examples"]
        if e["label"] == "PAN":
            assert not e["examples"]
