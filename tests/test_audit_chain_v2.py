from __future__ import annotations

import glob
import importlib
from pathlib import Path

import pytest

from secureprompt.audit import log as audit_log


def test_chain_and_tail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    importlib.reload(audit_log)

    first = audit_log.append({"event": "scrub", "operation_id": "op1"})
    second = audit_log.append({"event": "scrub", "operation_id": "op1"})

    assert second["prev_hash"] == first["hash"]

    rows = audit_log.tail(10)
    assert len(rows) == 2

    jsonl_files = glob.glob(str(tmp_path / "data" / "audit" / "audit-*.jsonl"))
    assert jsonl_files

    importlib.reload(audit_log)
