import json
from pathlib import Path
from scripts.migrate_receipts_actions import migrate_file

def test_migrate_adds_actions(tmp_path: Path):
    src = tmp_path / "rec.json"
    rec = {
        "entities": [
            {"label": "EMAIL", "c_level": "C3", "action": "UNKNOWN"},
            {"label": "PAN", "c_level": "C4", "action": ""},
            {"label": "NAME", "c_level": "C2"},
        ]
    }
    src.write_text(json.dumps(rec), encoding="utf-8")
    dst = tmp_path / "out.json"
    changed = migrate_file(src, dst)
    assert changed is True
    out = json.loads(dst.read_text(encoding="utf-8"))
    acts = [e["action"] for e in out["entities"]]
    assert acts == ["mask", "redact", "allow"]
