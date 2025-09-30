\
#!/usr/bin/env python3
import argparse, json, os, re, base64
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd
import yaml

def _read_config(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        return yaml.safe_load(f)

def _iter_files(patterns: List[str]) -> List[Path]:
    # robust, recursive globbing using glob.glob
    import glob
    out = []
    for pat in patterns:
        root = os.environ.get("EXTERNAL_ROOT", "external/SecurePrompt")
        pat = pat.replace("${external_root}", root)
        out.extend(Path(x) for x in glob.glob(pat, recursive=True))
    return [p for p in out if p.is_file() and not p.name.startswith('~$')]

def _sniff_delim(p: Path) -> str:
    sample = p.read_text(errors="ignore")[:2000]
    if sample.count(";") > sample.count(","): return ";"
    return ","

def norm_header(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[_\-\s]+", " ", s)
    return s

def _map_headers(cols: List[str]) -> Dict[str, str]:
    mapping = {}
    for c in cols:
        n = norm_header(str(c))
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

def read_tabular(path: Path):
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
            if rec["raw_text"] or rec["expected_scrub"]:
                records.append(rec)
    return records

def normalize_data(files: List[Path]) -> List[Dict[str, Any]]:
    records = []
    for p in files:
        if p.suffix.lower() in [".pdf", ".png", ".jpg", ".jpeg"]:
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

def ensure_policy_manifests(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    c2 = [
      {"id":"EMAIL_basic","label":"EMAIL","pattern":r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}","validator":"none","action":"mask","explanation":"email address","confidence":0.9},
      {"id":"PHONE_e164","label":"PHONE","pattern":r"\+?[1-9]\d{1,14}","validator":"none","action":"mask","explanation":"E.164 phone","confidence":0.85},
      {"id":"IPV4_basic","label":"IPV4","pattern":r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b","validator":"none","action":"mask","explanation":"IPv4 address","confidence":0.85},
      {"id":"IPV6_basic","label":"IPV6","pattern":r"\b([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b","validator":"none","action":"mask","explanation":"IPv6 address","confidence":0.8},
      {"id":"BIC_basic","label":"BIC","pattern":r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b","validator":"none","action":"mask","explanation":"SWIFT/BIC code","confidence":0.9},
    ]
    c3 = [
      {"id":"IBAN_generic","label":"IBAN","pattern":r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b","validator":"iban_checksum","action":"redact","explanation":"bank account IBAN","confidence":0.95},
      {"id":"IBAN_BE","label":"IBAN","pattern":r"\bBE\d{2}\s?(?:\d{4}\s?){3}\b","validator":"iban_checksum","action":"redact","explanation":"Belgian IBAN","confidence":0.96},
      {"id":"PAN_luhn","label":"PAN","pattern":r"\b(?:\d[ -]*?){13,19}\b","validator":"luhn","action":"redact","explanation":"payment card number","confidence":0.96},
      {"id":"ACCOUNT_ID_generic","label":"ACCOUNT_ID","pattern":r"\bACC[_-]?\d{6,}\b","validator":"none","action":"redact","explanation":"internal account id","confidence":0.8},
      {"id":"ADDRESS_be_like","label":"ADDRESS","pattern":r"(?i)\b([A-ZÀ-ÿ][a-zÀ-ÿ'\- ]+)\s+(straat|laan|lei|weg|steenweg|plein|dreef|kaai|ring)\s+\d+\w?\b","validator":"none","action":"redact","explanation":"street + number (BE style)","confidence":0.75},
    ]
    c4 = [
      {"id":"NATIONAL_ID_BE","label":"NATIONAL_ID","pattern":r"\b\d{2}[.\- ]?\d{2}[.\- ]?\d{2}[.\- ]?\d{3}[.\- ]?\d{2}\b","validator":"be_nrn","action":"redact","explanation":"Belgian national register number","confidence":0.9},
      {"id":"VAT_BE","label":"VAT_ID","pattern":r"\bBE0?\d{9}\b","validator":"none","action":"redact","explanation":"Belgian VAT number","confidence":0.9},
      {"id":"AUTH_secret","label":"AUTH_TOKEN","pattern":r"(?i)\b(api[_-]?key|secret|token|bearer)\b\s*[:=]\s*[A-Za-z0-9_\-]{16,}","validator":"none","action":"redact","explanation":"auth secret/token","confidence":0.9},
      {"id":"PASSWORD_inline","label":"PASSWORD","pattern":r"(?i)\b(pass(word)?|pwd)\b\s*[:=]\s*[^ \t\r\n]{6,}","validator":"none","action":"redact","explanation":"inline password","confidence":0.9},
      {"id":"DOB_generic","label":"DOB","pattern":r"\b(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})\b","validator":"date","action":"redact","explanation":"date of birth","confidence":0.7},
    ]
    import yaml
    for name, rules in [("c2.yml", c2), ("c3.yml", c3), ("c4.yml", c4)]:
        with open(outdir / name, "w") as f:
            yaml.safe_dump(rules, f, sort_keys=False, allow_unicode=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/datasets.yml")
    args = ap.parse_args()
    cfg = _read_config(args.config)

    prompts_files = _iter_files(cfg["inputs"]["prompts"])
    data_files = _iter_files(cfg["inputs"]["data"])

    prom_recs = normalize_prompts(prompts_files)
    data_recs = normalize_data(data_files)

    golden = [r for r in prom_recs if r.get("expected_scrub")]
    evals  = [r for r in prom_recs if not r.get("expected_scrub")] + data_recs

    out_golden = Path(cfg["output"]["golden_dir"]); out_golden.mkdir(parents=True, exist_ok=True)
    out_eval = Path(cfg["output"]["eval_dir"]); out_eval.mkdir(parents=True, exist_ok=True)
    out_policy = Path(cfg["output"]["policy_dir"]); out_policy.mkdir(parents=True, exist_ok=True)

    by_file = {}
    for r in golden:
        base = Path(r["source_path"]).stem
        by_file.setdefault(base, []).append(r)
    if by_file:
        for base, rows in by_file.items():
            write_jsonl(out_golden / f"{base}.jsonl", rows)
    else:
        write_jsonl(out_golden / "empty.jsonl", [])

    write_jsonl(out_eval / "eval.jsonl", evals)
    ensure_policy_manifests(out_policy)

    print(json.dumps({
        "counts": {
            "prompts_files": len(prompts_files),
            "data_files": len(data_files),
            "golden_records": sum(len(v) for v in by_file.values()),
            "eval_records": len(evals),
        }
    }, indent=2))

if __name__ == "__main__":
    main()
