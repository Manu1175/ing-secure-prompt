#!/usr/bin/env python3
import argparse, json, os, re, sys, base64, hashlib
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd
import yaml

def _read_config(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return yaml.safe_load(f)

def _iter_files(patterns: List[str]) -> List[Path]:
    out = []
    for pat in patterns:
        out.extend(Path().glob(pat.replace("${external_root}", os.environ.get("EXTERNAL_ROOT", "external/SecurePrompt"))))
    return [p for p in out if p.is_file()]

def _sniff_delim(p: Path) -> str:
    sample = p.read_text(errors="ignore")[:2000]
    if sample.count(";") > sample.count(","): return ";"
    return ","

def _norm_header(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[_\-\s]+", " ", s)
    return s

def _map_headers(cols: List[str]) -> Dict[str, str]:
    mapping = {}
    for c in cols:
        n = _norm_header(str(c))
        if re.search(r"^original prompt$|^prompt$|^text$|^input$", n):
            mapping[c] = "raw_text"
        elif re.search(r"^sanitized prompt$|^sanitized$", n):
            mapping[c] = "expected_scrub"
        elif re.search(r"^c$|confidential|confidentiality|level|c level", n):
            mapping[c] = "c_level"
        elif re.search(r"entities|labels|spans|annotations", n):
            mapping[c] = "entities"
        elif "response" in n and "sanitized" in n:
            mapping[c] = "sanitized_response"
        elif n == "response" or "original response" in n:
            mapping[c] = "response"
        elif "file" in n or "path" in n:
            mapping[c] = "source_path"
    return mapping

def _record_id(base: str, idx: int) -> str:
    return f"{base}:{idx}"

def read_tabular(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        try:
            return pd.read_csv(path)
        except Exception:
            return pd.read_csv(path, sep=_sniff_delim(path))
    elif path.suffix.lower() in [".xlsx", ".xls"]:
        xls = pd.ExcelFile(path)
        frames = []
        for sheet in xls.sheet_names:
            df = pd.read_excel(path, sheet_name=sheet)
            df["__sheet__"] = sheet
            frames.append(df)
        return pd.concat(frames, ignore_index=True)
    elif path.suffix.lower() == ".txt":
        txt = path.read_text(errors="ignore")
        return pd.DataFrame([{"raw_text": txt}])
    elif path.suffix.lower() == ".jsonl":
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        return pd.DataFrame(rows)
    else:
        return pd.DataFrame()

def normalize_prompts(files: List[Path]) -> List[Dict[str, Any]]:
    records = []
    for p in files:
        df = read_tabular(p)
        if df.empty: continue
        header_map = _map_headers(df.columns.tolist())
        base = p.stem
        for i, row in df.iterrows():
            rec = {
                "id": _record_id(base, i),
                "source_path": str(p),
                "modality": "text",
                "c_level": row.get(header_map.get("c_level", "c_level"), None),
                "raw_text": row.get(next((k for k,v in header_map.items() if v=="raw_text"), None), None),
                "expected_scrub": row.get(next((k for k,v in header_map.items() if v=="expected_scrub"), None), None),
                "entities": row.get(next((k for k,v in header_map.items() if v=="entities"), None), None),
                "notes": None,
            }
            # If both prompt and sanitized prompt are present, keep as golden
            if rec["raw_text"] or rec["expected_scrub"]:
                records.append(rec)
    return records

def normalize_data(files: List[Path]) -> List[Dict[str, Any]]:
    records = []
    for p in files:
        if p.suffix.lower() in [".pdf", ".png", ".jpg", ".jpeg"]:
            # keep only reference; tests may open bytes lazily
            with open(p, "rb") as f:
                blob = base64.b64encode(f.read()).decode("ascii")
            records.append({
                "id": _record_id(p.stem, 0),
                "source_path": str(p),
                "modality": "pdf" if p.suffix.lower()==".pdf" else "image",
                "c_level": None,
                "raw_text": None,
                "file_bytes_b64": blob,
                "expected_scrub": None,
                "entities": None,
                "notes": None,
            })
            continue
        df = read_tabular(p)
        if df.empty: 
            continue
        header_map = _map_headers(df.columns.tolist())
        base = p.stem
        for i, row in df.iterrows():
            # build a concatenated text payload for eval when no single prompt column exists
            raw = row.get(next((k for k,v in header_map.items() if v=="raw_text"), None), None)
            if raw is None:
                try:
                    raw = " | ".join(f"{k}={row[k]}" for k in df.columns if not str(k).startswith("__"))
                except Exception:
                    raw = None
            rec = {
                "id": _record_id(base, i),
                "source_path": str(p),
                "modality": "text",
                "c_level": row.get(header_map.get("c_level","c_level"), None),
                "raw_text": raw,
                "file_bytes_b64": None,
                "expected_scrub": row.get(next((k for k,v in header_map.items() if v=="expected_scrub"), None), None),
                "entities": row.get(next((k for k,v in header_map.items() if v=="entities"), None), None),
                "notes": None,
            }
            records.append(rec)
    return records

def write_jsonl(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def ensure_policy_manifests(policy_files: List[Path], outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    # minimal default manifests
    defaults = {
        "c2.yml": [
            {"id": "EMAIL_basic", "label": "EMAIL", "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "validator": "none", "action": "mask", "explanation": "email address", "confidence": 0.9},
            {"id": "PHONE_basic", "label": "PHONE", "pattern": r"\\+?\\d[\\d\\s().-]{7,}", "validator": "none", "action": "mask", "explanation": "phone number", "confidence": 0.85},
        ],
        "c3.yml": [
            {"id": "IBAN_basic", "label": "IBAN", "pattern": r"[A-Z]{2}\\d{2}[A-Z0-9]{1,30}", "validator": "iban_checksum", "action": "redact", "explanation": "bank account IBAN", "confidence": 0.95},
            {"id": "PAN_basic", "label": "PAN", "pattern": r"\\b(?:\\d[ -]*?){13,19}\\b", "validator": "luhn", "action": "redact", "explanation": "payment card number", "confidence": 0.95},
        ],
        "c4.yml": [
            {"id": "NID_basic", "label": "NATIONAL_ID", "pattern": r"\\b[0-9]{2}\\.[0-9]{2}\\.[0-9]{2}-[0-9]{3}\\.\\b|\\b[0-9]{11}\\b", "validator": "none", "action": "redact", "explanation": "national id", "confidence": 0.9},
            {"id": "AUTH_secret", "label": "AUTH_TOKEN", "pattern": r"(api[_-]?key|secret|token)\\s*[:=]\\s*[A-Za-z0-9_\\-]{16,}", "validator": "none", "action": "redact", "explanation": "auth secrets", "confidence": 0.9},
        ]
    }
    # try to enrich from provided policy-like spreadsheets (if any)
    for name, rules in defaults.items():
        with open(outdir / name, "w") as f:
            yaml.safe_dump(rules, f, sort_keys=False)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/datasets.yml")
    args = ap.parse_args()

    cfg = _read_config(args.config)
    prompts_files = _iter_files(cfg["inputs"]["prompts"])
    data_files = _iter_files(cfg["inputs"]["data"])

    # Normalize
    prom_recs = normalize_prompts(prompts_files)
    data_recs = normalize_data(data_files)

    # Split: golden = have expected_scrub; eval = others
    golden = [r for r in prom_recs if r.get("expected_scrub")]
    evals  = [r for r in prom_recs if not r.get("expected_scrub")] + data_recs

    # Write
    out_golden = Path(cfg["output"]["golden_dir"])
    out_eval = Path(cfg["output"]["eval_dir"])
    out_policy = Path(cfg["output"]["policy_dir"])

    out_golden.mkdir(parents=True, exist_ok=True)
    out_eval.mkdir(parents=True, exist_ok=True)

    # shard golden by file base
    by_file = {}
    for r in golden:
        base = Path(r["source_path"]).stem
        by_file.setdefault(base, []).append(r)
    if by_file:
        for base, rows in by_file.items():
            write_jsonl(out_golden / f"{base}.jsonl", rows)
    else:
        # ensure at least one file exists
        write_jsonl(out_golden / "empty.jsonl", [])

    # eval data single file
    write_jsonl(out_eval / "eval.jsonl", evals)

    # policies
    ensure_policy_manifests(_iter_files(cfg.get("policy_hints", [])), Path(cfg["output"]["policy_dir"]))

    # simple report
    report = {
        "counts": {
            "prompts_files": len(prompts_files),
            "data_files": len(data_files),
            "golden_records": sum(len(v) for v in by_file.values()),
            "eval_records": len(evals),
        }
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
