import json, subprocess, sys, os, pathlib

def test_ingest_runs(tmp_path):
    # ensure command runs and creates output files
    root = pathlib.Path(__file__).resolve().parents[1]
    cfg = root / "config" / "datasets.yml"
    env = os.environ.copy()
    # allow running even if external folder not present
    (root / "external" / "SecurePrompt").mkdir(parents=True, exist_ok=True)
    subprocess.check_call([sys.executable, str(root / "tools" / "ingest_secureprompt_repo.py"), "--config", str(cfg)], env=env)
    assert (root / "data" / "golden").exists()
    assert (root / "data" / "eval" / "eval.jsonl").exists()
