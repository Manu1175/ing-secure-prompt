import subprocess, sys, os, pathlib

def test_ingest_runs(tmp_path):
    root = pathlib.Path(__file__).resolve().parents[1]
    cfg = root / "config" / "datasets.yml"
    env = os.environ.copy()
    (root / "external" / "SecurePrompt").mkdir(parents=True, exist_ok=True)
    subprocess.check_call([sys.executable, str(root / "tools" / "ingest_secureprompt_repo.py"), "--config", str(cfg)], env=env)
    assert (root / "data" / "golden").exists()
    assert (root / "policy" / "manifests" / "c3.yml").exists()
