from __future__ import annotations

import json
from pathlib import Path

from secureprompt.audit.log import AuditLog


def test_audit_log_hash_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    log = AuditLog(str(path))

    first = log.append({"action": "first"})
    second = log.append({"action": "second"})

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    first_entry = json.loads(lines[0])
    second_entry = json.loads(lines[1])

    assert first_entry["curr_hash"] == second_entry["prev_hash"]
    assert second == second_entry["curr_hash"]
