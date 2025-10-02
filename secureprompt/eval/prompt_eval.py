from __future__ import annotations

import os
import json
import time
import collections
import re
import difflib
from typing import Dict, Any, List, Tuple, Optional, Iterable

import httpx
from openpyxl import load_workbook, Workbook
from openpyxl.utils import get_column_letter

__all__ = [
    "evaluate_workbook",
    "tokens_of",
    "normalize_token",
    "make_eval_sanitized",
    "minimal_diff",
]

# Accept both <FOO> and [FOO]
TOKEN_RX = re.compile(r"[<\[]([A-Z0-9_]+)[>\]]")

# Recognize scrubbed-style tags like C3::EMAIL::deadbeef10
SCRUB_TAG_RX = re.compile(r"\bC[1-5]::([A-Z0-9_]+)::[0-9a-f]{8,40}\b")

def tokens_of(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [m.group(1) for m in TOKEN_RX.finditer(s)]

def normalize_token(t: str) -> str:
    p = re.sub(r"__+", "_", t.strip().upper())
    if p and p[-1].isdigit():
        p = p[:-1]
    return p

def _columns(ws) -> Dict[str, int]:
    hdr = [c.value for c in next(ws.iter_rows(min_row=1, max_row=1))]
    return {name: idx for idx, name in enumerate(hdr)}

def _best_raw_prompt_row(row_cells: List[Any], names: Dict[str, int]) -> Optional[str]:
    for key in ("Prompt", "Original Prompt", "Original", "Input", "Raw"):
        if key in names:
            v = row_cells[names[key]]
            if v:
                return v
    return None

def _http_post_scrub(api: str, text: str, clearance: str) -> Tuple[Optional[Dict[str, Any]], float]:
    t0 = time.time()
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(
                f"{api.rstrip('/')}/scrub",
                json={"text": text, "clearance": clearance},
            )
            latency_ms = (time.time() - t0) * 1000.0
            if resp.status_code == 200:
                return resp.json(), latency_ms
    except Exception:
        pass
    return None, (time.time() - t0) * 1000.0

def _ensure_output_dir(outdir: str):
    os.makedirs(outdir, exist_ok=True)

def _write_summary(path: str, data: Dict[str, Any]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def _write_anomalies_md(path: str, missing_counts: List[Tuple[str, int]]):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Prompt Evaluator – Anomalies\n\n")
        if not missing_counts:
            f.write("No systematic missing tokens detected.\n")
            return
        f.write("## Top missing tokens (gold present, got absent)\n\n")
        for t, n in missing_counts[:30]:
            f.write(f"- {t}: {n}\n")

def _bracket_style() -> Tuple[str, str]:
    style = os.environ.get("SP_TOKEN_STYLE", "square").strip().lower()
    return ("[", "]") if style != "angle" else ("<", ">")

def _label_token(label: str) -> str:
    l, r = _bracket_style()
    return f"{l}{normalize_token(label)}{r}"

def _span_from_entity(e: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    if "start" in e and "end" in e and isinstance(e["start"], int) and isinstance(e["end"], int):
        return (e["start"], e["end"])
    sp = e.get("span")
    if isinstance(sp, (list, tuple)) and len(sp) == 2 and all(isinstance(x, int) for x in sp):
        return (sp[0], sp[1])
    return None

def make_eval_sanitized(raw_text: str, entities: List[Dict[str, Any]]) -> str:
    if not raw_text or not entities:
        return raw_text or ""
    out = raw_text
    repls: List[Tuple[int, int, str]] = []
    for e in entities:
        span = _span_from_entity(e)
        label = e.get("label")
        if span and label:
            s, t = span
            if 0 <= s <= t <= len(raw_text):
                repls.append((s, t, _label_token(label)))
    repls.sort(key=lambda x: (x[0], x[1]), reverse=True)
    for s, t, tok in repls:
        out = out[:s] + tok + out[t:]
    return out

def _fallback_tokenize_from_scrubbed(scrubbed: str) -> str:
    if not scrubbed:
        return ""
    return SCRUB_TAG_RX.sub(lambda m: _label_token(m.group(1)), scrubbed)

def _ensure_eval_columns(ws) -> Dict[str, int]:
    names = _columns(ws)
    def _need(name: str):
        nonlocal ws, names
        if name not in names:
            ws.cell(row=1, column=ws.max_column + 1, value=name)
            names = _columns(ws)
    _need("Got_Sanitized_Prompt")
    _need("Got_Sanitized_Prompt_Eval")
    _need("Gold_Tokens")
    _need("Got_Tokens")
    _need("TP")
    _need("FP")
    _need("FN")
    _need("Missing_Tokens")
    _need("Extra_Tokens")
    _need("Entities_Count")
    _need("APICallMs")
    _need("Diff_Gold_vs_GotEval")
    return names

def minimal_diff(a: str, b: str, max_chars: int = 1000) -> str:
    a = a or ""
    b = b or ""
    sm = difflib.SequenceMatcher(a=a, b=b)
    parts: List[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            parts.append(b[j1:j2])
        elif tag == "insert":
            parts.append("[+" + b[j1:j2] + "+]")
        elif tag == "delete":
            parts.append("[-" + a[i1:i2] + "-]")
        elif tag == "replace":
            parts.append("[-" + a[i1:i2] + "-][+" + b[j1:j2] + "+]")
    out = "".join(parts)
    if len(out) > max_chars:
        return out[: max_chars - 3] + "..."
    return out

def _apply_column_hiding(ws, keep_cols: Optional[Iterable[str]], topk: int) -> None:
    if not (keep_cols or topk > 0):
        return
    names = _columns(ws)
    keep_set: set[str] = set()
    if keep_cols:
        target = {c.strip().lower() for c in keep_cols if c and str(c).strip()}
        for name, idx in names.items():
            if name and name.strip().lower() in target:
                keep_set.add(name)
    if not keep_set and topk > 0:
        priority = [
            "Prompt", "Original Prompt", "Original", "Input",
            "Sanitized Prompt",
            "Got_Sanitized_Prompt_Eval",
            "TP", "FN", "FP",
            "Missing_Tokens", "Extra_Tokens",
            "APICallMs", "Entities_Count",
            "Got_Sanitized_Prompt",
            "Gold_Tokens", "Got_Tokens",
        ]
        for name in priority:
            if name in names:
                keep_set.add(name)
                if len(keep_set) >= topk:
                    break
    for name, idx in names.items():
        col_letter = get_column_letter(idx + 1)
        if name not in keep_set:
            ws.column_dimensions[col_letter].hidden = True

def _add_anomalies_sheet(wb: Workbook, rows_meta: List[Dict[str, Any]], top_missing: List[Tuple[str, int]]) -> None:
    ws = wb.create_sheet("Anomalies")
    ws.append([
        "Row", "Missing_Tokens", "Extra_Tokens",
        "Gold_Tokens", "Got_Tokens",
        "TP", "FP", "FN", "Entities_Count", "APICallMs",
    ])
    for m in rows_meta:
        if m["missing"] or m["extra"]:
            ws.append([
                m["row"],
                ", ".join(sorted(m["missing"])) if m["missing"] else "",
                ", ".join(sorted(m["extra"])) if m["extra"] else "",
                ", ".join(sorted(m["E"])) if m["E"] else "",
                ", ".join(sorted(m["G"])) if m["G"] else "",
                m["tp"], m["fp"], m["fn"], m["entities"], m["lat_ms"],
            ])
    ws.append([])
    ws.append(["Top Missing Tokens", "Count"])
    for tok, cnt in top_missing[:50]:
        ws.append([tok, cnt])

def _load_aliases_dict(aliases: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if aliases:
        for k, v in aliases.items():
            out[normalize_token(k)] = normalize_token(v)
    env_json = os.environ.get("SP_TOKEN_ALIASES_JSON", "").strip()
    if env_json:
        try:
            extra = json.loads(env_json)
            for k, v in extra.items():
                out[normalize_token(k)] = normalize_token(v)
        except Exception:
            pass
    return out

def _apply_aliases(tokens: Iterable[str], alias_map: Dict[str, str]) -> List[str]:
    out = []
    for t in tokens:
        nt = normalize_token(t)
        out.append(alias_map.get(nt, nt))
    return out

def evaluate_workbook(
    input_path: str,
    clearance: str = "C3",
    outdir: str = "reports",
    add_anomalies_sheet: bool = True,
    keep_cols: Optional[List[str]] = None,
    keep_topk: int = 0,
    diff_mode: str = "gold",  # "gold", "raw", "none"
    eval_source: str = "auto",  # "auto", "scrubbed", "spans"
    aliases: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    _ensure_output_dir(outdir)
    wb = load_workbook(input_path)
    ws = wb.active

    names = _ensure_eval_columns(ws)
    gold_col = names.get("Sanitized Prompt")
    if gold_col is None:
        raise ValueError("Workbook must contain 'Sanitized Prompt' header (gold).")

    got_col          = names["Got_Sanitized_Prompt"]
    got_eval_col     = names["Got_Sanitized_Prompt_Eval"]
    gold_tokens_col  = names["Gold_Tokens"]
    got_tokens_col   = names["Got_Tokens"]
    tp_col           = names["TP"]
    fp_col           = names["FP"]
    fn_col           = names["FN"]
    miss_col         = names["Missing_Tokens"]
    extra_col        = names["Extra_Tokens"]
    ents_cnt_col     = names["Entities_Count"]
    latency_col      = names["APICallMs"]
    diff_col         = names["Diff_Gold_vs_GotEval"]

    api = os.environ.get("SCRUB_API", "http://127.0.0.1:8000")
    alias_map = _load_aliases_dict(aliases)

    tp = fp = fn = 0
    total_entities = 0
    missing_counter = collections.Counter()
    rows = 0
    rows_meta: List[Dict[str, Any]] = []

    for i, r in enumerate(ws.iter_rows(min_row=2, values_only=False), start=2):
        rows += 1
        cells = [c.value for c in r]
        raw = _best_raw_prompt_row(cells, names)
        gold = cells[gold_col] if gold_col is not None else None

        got_sanitized: Optional[str] = None
        got_eval: Optional[str] = None
        entities: List[Dict[str, Any]] = []
        latency_ms: float = 0.0

        if raw:
            payload, latency_ms = _http_post_scrub(api, raw, clearance)
            if payload:
                got_sanitized = payload.get("scrubbed")
                entities = payload.get("entities") or []
                total_entities += len(entities)
                if eval_source == "scrubbed":
                    got_eval = _fallback_tokenize_from_scrubbed(got_sanitized or "")
                else:
                    got_eval = make_eval_sanitized(raw, entities)
                    if eval_source == "auto" and got_eval == raw and got_sanitized:
                        got_eval = _fallback_tokenize_from_scrubbed(got_sanitized)
            else:
                got_sanitized = None
                got_eval = None

        r[got_col].value = got_sanitized
        r[got_eval_col].value = got_eval
        r[ents_cnt_col].value = len(entities) if entities else 0
        r[latency_col].value = round(latency_ms, 2)

        E_raw = tokens_of(gold)
        G_raw = tokens_of(got_eval)
        E = set(_apply_aliases(E_raw, alias_map))
        G = set(_apply_aliases(G_raw, alias_map))

        r[gold_tokens_col].value = ", ".join(sorted(E)) if E else ""
        r[got_tokens_col].value  = ", ".join(sorted(G)) if G else ""

        hit = E & G
        extra = G - E
        miss = E - G
        r[tp_col].value = len(hit)
        r[fp_col].value = len(extra)
        r[fn_col].value = len(miss)
        r[miss_col].value = ", ".join(sorted(miss)) if miss else ""
        r[extra_col].value = ", ".join(sorted(extra)) if extra else ""

        if diff_mode == "gold":
            r[diff_col].value = minimal_diff(gold or "", got_eval or "")
        elif diff_mode == "raw":
            r[diff_col].value = minimal_diff(raw or "", got_eval or "")
        else:
            r[diff_col].value = ""

        missing_counter.update(miss)
        tp += len(hit)
        fp += len(extra)
        fn += len(miss)

        rows_meta.append({
            "row": i,
            "E": E, "G": G,
            "missing": miss, "extra": extra,
            "tp": len(hit), "fp": len(extra), "fn": len(miss),
            "entities": len(entities), "lat_ms": round(latency_ms, 2),
        })

    if add_anomalies_sheet:
        _add_anomalies_sheet(wb, rows_meta, missing_counter.most_common())
    _apply_column_hiding(ws, keep_cols=keep_cols, topk=keep_topk)

    out_xlsx = os.path.join(outdir, os.path.basename(input_path).replace(".xlsx", "_eval.xlsx"))
    wb.save(out_xlsx)

    tot = tp + fn
    prompt_acc = (tp / tot) if tot else 0.0

    summary = {
        "rows": rows,
        "prompt_accuracy": prompt_acc,
        "response_accuracy": None,
        "total_response_entities": total_entities,
        "tp": tp, "fp": fp, "fn": fn,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input": input_path,
        "workbook": out_xlsx,
        "api": api,
        "top_missing": missing_counter.most_common(20),
        "diff_mode": diff_mode,
        "keep_topk": keep_topk,
        "kept_columns": keep_cols or [],
        "anomalies_sheet": add_anomalies_sheet,
        "eval_source": eval_source,
        "aliases_size": len(alias_map),
    }
    _write_summary(os.path.join(outdir, "prompt_eval_summary.json"), summary)
    _write_anomalies_md(os.path.join(outdir, "prompt_eval_anomalies.md"), missing_counter.most_common())
    return summary
