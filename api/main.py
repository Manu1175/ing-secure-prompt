"""FastAPI entry point for SecurePrompt UI and JSON APIs."""

from __future__ import annotations

import hashlib
import logging
import json
import os
import re
import tempfile
import io
import jinja2
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import (
    Body,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
    Query,
)
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    StreamingResponse,
    JSONResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from secureprompt.scrub.pipeline import scrub_text
from secureprompt.receipts.store import read_receipt
from secureprompt.receipts.descrub import descrub_text

from secureprompt.files.text import load_text
from secureprompt.files.pdf import extract_pdf_text
from secureprompt.files.ocr import ocr_image_to_text
from secureprompt.files.xlsx import scrub_workbook
from secureprompt.prompt.lexicon import iter_spans as _lex_iter_spans
from secureprompt.audit.store import AuditStore
from secureprompt.descrub.service import descrub as _descrub

try:  # pragma: no cover - optional helper
    from secureprompt.files.redact import write_redacted_text
except Exception:  # pragma: no cover - degrade gracefully
    write_redacted_text = None  # type: ignore[attr-defined]

from secureprompt.audit import log as audit_log
from secureprompt.ui import scoring as ui_scoring

REDACTED_DIR = Path("data/out")
REDACTED_DIR.mkdir(parents=True, exist_ok=True)

REDACTED_XLSX_DIR = Path("data/redacted")
REDACTED_XLSX_DIR.mkdir(parents=True, exist_ok=True)

RECEIPTS_DIR = Path("data/receipts")
RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)

KEEP_ORIG = os.environ.get("KEEP_ORIGINAL_IN_RECEIPTS", "").lower() not in {"", "0", "false", "no"}

BASELINE_PATH = Path(os.environ.get("SECUREPROMPT_BASELINE_PATH", "reports/baseline_counts.json"))

ACTIONS_ALLOW = {"admin", "auditor"}
ALLOWED_DESCRUB_ROLES = [
    r.strip().lower()
    for r in os.getenv("SECUREPROMPT_DESCRUB_ROLES", "auditor").split(",")
    if r.strip()
]
CLEARANCE_OPTIONS = ("C1", "C2", "C3", "C4")
TEXT_EXTENSIONS = {".txt", ".text", ".html", ".htm", ".csv"}
ALLOWED_EXTENSIONS = TEXT_EXTENSIONS | {".pdf", ".png", ".xlsx"}

logger = logging.getLogger("secureprompt.ui.scrub")

_FALSEY = {"", "0", "false", "no", "off"}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in _FALSEY


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    return val if val >= 0 else default


def _env_list(name: str) -> List[str]:
    raw = os.environ.get(name)
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return [str(item) for item in parsed]
    items: List[str] = []
    for chunk in raw.replace(";", "\n").splitlines():
        for part in chunk.split(","):
            part = part.strip()
            if part:
                items.append(part)
    return items


def _scrub_default_c_level() -> str:
    raw = os.environ.get("SCRUB_DEFAULT_C_LEVEL") or os.environ.get("DEFAULT_C_LEVEL")
    if not raw:
        return "C3"
    candidate = raw.strip().upper()
    return candidate if candidate in CLEARANCE_OPTIONS else "C3"


def _scrub_upload_max_mb() -> int:
    for key in ("SCRUB_UPLOAD_MAX_MB", "UPLOAD_MAX_MB"):
        raw = os.environ.get(key)
        if raw:
            try:
                val = int(raw)
                if val > 0:
                    return val
            except ValueError:
                continue
    return 10


def _scrub_workbook_allowed() -> bool:
    for key in ("SCRUB_WORKBOOK_ALLOWED", "WORKBOOK_ALLOWED"):
        if os.environ.get(key) is not None:
            return _env_bool(key, True)
    return True


def _scrub_examples() -> List[str]:
    for key in ("SCRUB_EXAMPLES_JSON", "SCRUB_EXAMPLES"):
        items = _env_list(key)
        if items:
            return items
    return []


def _ensure_entity_value(ent: Dict[str, Any], original: str) -> None:
    if ent.get("value"):
        return
    s, e = ent.get("start"), ent.get("end")
    if isinstance(s, int) and isinstance(e, int) and 0 <= s < e <= len(original):
        ent["value"] = original[s:e]


def _format_entities_for_view(entities: Optional[List[Dict[str, Any]]]) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    formatted: List[Dict[str, Any]] = []
    counts: Counter[str] = Counter()
    if not entities:
        return formatted, {}
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        label = str(entity.get("label") or "").strip().upper()
        value = entity.get("value")
        if value is None:
            value = entity.get("text") or entity.get("original") or ""
        start = entity.get("start") if isinstance(entity.get("start"), int) else None
        end = entity.get("end") if isinstance(entity.get("end"), int) else None
        c_level = entity.get("c_level") or entity.get("clearance") or entity.get("c_level_required") or ""
        if label:
            counts[label] += 1
        formatted.append(
            {
                "label": label or "—",
                "value": str(value) if value is not None else "",
                "start": start,
                "end": end,
                "c_level": str(c_level) if c_level else "—",
            }
        )
    return formatted, dict(counts)


def _scrub_context(
    request: Request,
    clearance: str,
    *,
    upload_max_mb: Optional[int] = None,
    workbook_allowed: Optional[bool] = None,
    default_c_level: Optional[str] = None,
    keep_original: Optional[bool] = None,
    examples: Optional[List[str]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {
        "request": request,
        "clearance": clearance,
        "clearances": CLEARANCE_OPTIONS,
        "default_c_level": default_c_level if default_c_level is not None else _scrub_default_c_level(),
        "KEEP_ORIGINAL_IN_RECEIPTS": keep_original if keep_original is not None else _env_bool("KEEP_ORIGINAL_IN_RECEIPTS", False),
        "upload_max_mb": upload_max_mb if upload_max_mb is not None else _scrub_upload_max_mb(),
        "workbook_allowed": workbook_allowed if workbook_allowed is not None else _scrub_workbook_allowed(),
        "examples": examples if examples is not None else _scrub_examples(),
        "original_text": "",
        "sanitized_text": "",
        "operation_id": None,
        "audit_url": None,
        "error": None,
        "counts": {},
        "hashes": {},
        "saved_href": None,
        "saved_path": None,
        "receipt_path": None,
        "entities": [],
        "entity_counts": {},
        "baseline_ctx": None,
    }
    ctx.update(extra)
    return ctx


_LABEL_PRIORITY = {
    "DOCUMENT_TYPE": 20,
    "YEAR": 15,
    "LINK": 15,
    "AMOUNT": 15,
    "DATE": 15,
    "IBAN": 30,
    "BIC": 25,
    "PAN": 40,
    "EMAIL": 35,
    "PHONE": 35,
    "IPV4": 25,
    "IPV6": 25,
    "NATIONAL_ID": 40,
    "NAME": 1,
}


def _label_token(label: str) -> str:
    return f"<{label.strip().upper()}>"


def _span_from_entity(entity: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    if isinstance(entity.get("start"), int) and isinstance(entity.get("end"), int):
        return (entity["start"], entity["end"])
    span = entity.get("span")
    if isinstance(span, (list, tuple)) and len(span) == 2 and all(isinstance(x, int) for x in span):
        return (span[0], span[1])
    return None


def _combine_and_tokenize(raw_text: str, entities: Optional[List[Dict[str, Any]]]) -> str:
    if not raw_text:
        return ""

    spans: List[Dict[str, Any]] = []

    for entity in entities or []:
        span = _span_from_entity(entity)
        label = (entity.get("label") or "").strip().upper()
        if span and label:
            start, end = span
            if 0 <= start <= end <= len(raw_text):
                spans.append(
                    {
                        "start": start,
                        "end": end,
                        "label": label,
                        "priority": 100 + _LABEL_PRIORITY.get(label, 10),
                        "src": "entity",
                    }
                )

    for lex_span in _lex_iter_spans(raw_text):
        label = (lex_span["label"] or "").strip().upper()
        spans.append(
            {
                "start": int(lex_span["start"]),
                "end": int(lex_span["end"]),
                "label": label,
                "priority": _LABEL_PRIORITY.get(label, 10),
                "src": "lex",
            }
        )

    spans.sort(key=lambda item: (-item["priority"], -(item["end"] - item["start"]), item["start"]))

    selected: List[Dict[str, Any]] = []

    def _overlaps(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        return not (a["end"] <= b["start"] or a["start"] >= b["end"])

    for span in spans:
        if any(_overlaps(span, existing) for existing in selected):
            continue
        selected.append(span)

    selected.sort(key=lambda item: (item["start"], item["end"]), reverse=True)
    out = raw_text
    for span in selected:
        out = out[: span["start"]] + _label_token(span["label"]) + out[span["end"] :]
    return out

class ScrubRequest(BaseModel):
    text: str
    c_level: str = "C3"
    filename: Optional[str] = None


class ScrubResponse(BaseModel):
    original_hash: str
    scrubbed: str
    scrubbed_mask: Optional[str] = None
    scrubbed_tokens: Optional[str] = None
    entities: List[Dict[str, Any]]
    operation_id: str
    receipt_path: str


class ScrubWithFileResponse(ScrubResponse):
    output_path: str


class DescrubRequest(BaseModel):
    operation_id: str = Field(..., min_length=8)
    identifiers: List[str] = Field(default_factory=list)
    justification: Optional[str] = Field(default=None, min_length=5)

    class Config:
        extra = "allow"


class DescrubResponse(BaseModel):
    descrubbed: str
    operation_id: Optional[str] = None


app = FastAPI(title="SecurePrompt", version="0.2.0")

# ---------- De-scrub config ----------
ALLOWED_DESCRUB_ROLES = {
    r.strip()
    for r in os.environ.get("SECUREPROMPT_DESCRUB_ROLES", "").split(",")
    if r.strip()
}


def _load_receipt_by_op(op_id: str) -> dict:
    base = RECEIPTS_DIR
    p = base / f"{op_id}.json"
    if not p.exists():
        matches = list(base.glob(f"{op_id}*.json"))
        if matches:
            matches.sort()
            p = matches[0]
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"receipt not found for op '{op_id}'")
    try:
        return json.loads(p.read_text())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"bad receipt JSON: {exc}")


def _extract_original_payload(rec: dict) -> Optional[str]:
    for key in ("original", "input", "raw", "text", "payload", "body"):
        val = rec.get(key)
        if isinstance(val, str) and val.strip():
            return val
    for parent_key in ("request", "data"):
        sub = rec.get(parent_key)
        if isinstance(sub, dict):
            for key in ("original", "input", "raw", "text", "payload", "body"):
                val = sub.get(key)
                if isinstance(val, str) and val.strip():
                    return val
    return None


def _maybe_store_original(
    receipt_path: Optional[str],
    *,
    text: Optional[str] = None,
    raw_text: Optional[str] = None,
) -> None:
    if not KEEP_ORIG or not receipt_path:
        return

    try:
        path = Path(receipt_path)
    except Exception:
        return

    if not path.exists():
        fallback = RECEIPTS_DIR / path.name
        if fallback.exists():
            path = fallback
        else:
            return

    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return

    if receipt.get("original"):
        return

    original_value = None
    if text and text.strip():
        original_value = text
    elif raw_text and raw_text.strip():
        original_value = raw_text

    if not original_value:
        return

    receipt["original"] = original_value

    try:
        path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


@app.get("/descrub/{operation_id}")
def descrub(operation_id: str, role: str = Query(...), just: str = Query("", max_length=200)):
    if role not in ALLOWED_DESCRUB_ROLES:
        raise HTTPException(status_code=403, detail="role not allowed")

    rec = _load_receipt_by_op(operation_id)
    original = _extract_original_payload(rec)
    if not original:
        raise HTTPException(status_code=404, detail="original payload not stored in this receipt")

    return JSONResponse(
        {
            "operation_id": operation_id,
            "role": role,
            "justification": just,
            "original": original,
            "receipt_meta": {
                "endpoint": rec.get("endpoint"),
                "ts": rec.get("ts"),
                "actor": rec.get("actor"),
            },
        }
    )
app.mount("/files", StaticFiles(directory=REDACTED_DIR), name="files")
app.mount("/redacted", StaticFiles(directory=REDACTED_XLSX_DIR), name="redacted")
app.mount("/receipts", StaticFiles(directory=RECEIPTS_DIR), name="receipts")

AUDIT = AuditStore(Path(os.environ.get("SECUREPROMPT_AUDIT_JSONL", "data/audit.jsonl")))


def _default_actor(role: str = "system") -> Dict[str, str]:
    return {
        "username": "placeholder",
        "role": role,
        "session_id": "sess_placeholder",
    }


def _client_meta(request: Optional[Request]) -> Dict[str, str]:
    client_host = request.client.host if request and request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "placeholder") if request else "placeholder"
    return {
        "ip": client_host,
        "user_agent": user_agent,
        "device_id": "placeholder",
        "browser_id": "placeholder",
    }


def _sha256_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    file_path = Path(path)
    if not file_path.exists():
        return None
    h = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _emit_audit_event(event: Dict[str, Any]) -> None:
    try:  # pragma: no cover - best-effort logging
        audit_log.append(event)
    except Exception:
        pass


def _file_size(path: Optional[str]) -> int:
    if not path:
        return 0
    file_path = Path(path)
    if not file_path.exists():
        return 0
    return file_path.stat().st_size


def _baseline_context(
    *,
    file_name: Optional[str],
    clearance: str,
    entities: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if not file_name:
        return {"has_baseline": False}

    baseline_data = ui_scoring.load_baseline(BASELINE_PATH)
    if not baseline_data:
        return {"has_baseline": False, "filename": file_name}

    expected = ui_scoring.expected_for_file(baseline_data, file_name, clearance)
    achieved = ui_scoring.achieved_counts(entities)

    if not expected.get("by_label"):
        return {"has_baseline": False, "filename": file_name}

    scoring_result = ui_scoring.score(expected, achieved)

    labels = sorted(set(expected["by_label"].keys()) | set(achieved["by_label"].keys()))
    label_rows = [
        {
            "label": label,
            "expected": expected["by_label"].get(label, 0),
            "achieved": achieved["by_label"].get(label, 0),
        }
        for label in labels
    ]

    levels = sorted(set(expected["by_c_level"].keys()) | set(achieved["by_c_level"].keys()))
    level_rows = [
        {
            "level": level,
            "expected": expected["by_c_level"].get(level, 0),
            "achieved": achieved["by_c_level"].get(level, 0),
        }
        for level in levels
    ]

    return {
        "has_baseline": True,
        "filename": file_name,
        "clearance": clearance,
        "expected": expected,
        "achieved": achieved,
        "score": scoring_result.get("score", 0.0),
        "diff": scoring_result.get("diff", {}),
        "label_rows": label_rows,
        "level_rows": level_rows,
    }


def _entity_counts(entities: List[Dict[str, Any]], clearance: str) -> Dict[str, Any]:
    return audit_log.summarize_entities(entities, clearance)


def _hashes_payload(
    *,
    original_hash: Optional[str],
    scrubbed_text: Optional[str],
    receipt_path: Optional[str],
) -> Dict[str, Optional[str]]:
    scrubbed_hash = (
        hashlib.sha256(scrubbed_text.encode("utf-8")).hexdigest() if scrubbed_text else None
    )
    receipt_hash = _sha256_file(receipt_path)
    return {
        "original_sha256": original_hash,
        "scrubbed_sha256": scrubbed_hash,
        "receipt_sha256": receipt_hash,
    }


def _load_uploaded_text(path: Path, suffix: str) -> str:
    if suffix in TEXT_EXTENSIONS:
        return load_text(path)
    if suffix == ".pdf":
        return extract_pdf_text(path)
    if suffix == ".png":
        return ocr_image_to_text(str(path))
    raise ValueError(f"Unsupported file type: {suffix}")


async def _ingest_upload(upload: UploadFile, *, max_bytes: Optional[int] = None) -> str:
    filename = upload.filename or "upload.txt"
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file type. Allowed: .txt, .html, .csv, .pdf, .png, .xlsx")

    limit = (max_bytes + 1) if max_bytes is not None else None
    data = await upload.read(limit)
    if max_bytes is not None and len(data) > max_bytes:
        raise ValueError("Upload exceeds size limit")
    if not data:
        return ""

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        temp_path = Path(tmp.name)

    try:
        return _load_uploaded_text(temp_path, suffix)
    finally:
        temp_path.unlink(missing_ok=True)


async def _save_upload_to_tempfile(upload: UploadFile, *, max_bytes: Optional[int] = None) -> Path:
    filename = upload.filename or "upload"
    suffix = Path(filename).suffix or ".tmp"
    limit = (max_bytes + 1) if max_bytes is not None else None
    data = await upload.read(limit)
    if max_bytes is not None and len(data) > max_bytes:
        raise ValueError("Upload exceeds size limit")
    if not data:
        raise ValueError("Uploaded file is empty")
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        return Path(tmp.name)


def _render_dashboard(
    request: Request,
    *,
    clearance: str,
    original: Optional[str] = None,
    sanitized: Optional[str] = None,
    entities: Optional[List[Dict[str, Any]]] = None,
    error: Optional[str] = None,
    file_name: Optional[str] = None,
    saved_path: Optional[str] = None,
    saved_href: Optional[str] = None,
    operation_id: Optional[str] = None,
    receipt_path: Optional[str] = None,
    counts: Optional[Dict[str, Any]] = None,
    hashes: Optional[Dict[str, Optional[str]]] = None,
    baseline_ctx: Optional[Dict[str, Any]] = None,
) -> HTMLResponse:
    context = {
        "request": request,
        "clearance": clearance,
        "clearances": CLEARANCE_OPTIONS,
        "original": original or "",
        "sanitized": sanitized or "",
        "entities": entities or [],
        "error": error,
        "file_name": file_name,
        "saved_path": saved_path,
        "saved_href": saved_href,
        "operation_id": operation_id,
        "receipt_path": receipt_path,
        "counts": counts,
        "hashes": hashes,
        "baseline_ctx": baseline_ctx,
    }
    return templates.TemplateResponse(request, "dashboard.html", context)


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/scrub", response_model=ScrubResponse)
def api_scrub(request: Request, req: ScrubRequest = Body(...)) -> ScrubResponse:
    result = scrub_text(req.text, req.c_level)

    raw_text = req.text or ""
    for entity in result.get("entities") or []:
        _ensure_entity_value(entity, raw_text)
    _maybe_store_original(result.get("receipt_path"), text=req.text, raw_text=raw_text)
    tokenized = _combine_and_tokenize(raw_text, result.get("entities") or [])

    result["scrubbed_mask"] = result.get("scrubbed") or ""
    result["scrubbed_tokens"] = tokenized
    result["scrubbed"] = tokenized

    actor = (request.headers.get("X-Actor") or "api").strip()
    client_ip = request.client.host if request.client else None

    scrubbed_bytes = (tokenized or "").encode("utf-8")
    scrubbed_hash = hashlib.sha256(scrubbed_bytes).hexdigest()

    AUDIT.append({
        "actor": actor,
        "endpoint": "/scrub",
        "client_ip": client_ip,
        "c_level": req.c_level,
        "original_hash": result.get("original_hash"),
        "scrubbed_hash": scrubbed_hash,
        "latency_ms": result.get("latency_ms") or result.get("latencyMs"),
        "entities": [
            {
                "label": entity.get("label"),
                "c_level": entity.get("c_level") or entity.get("cLevel"),
                "detector": entity.get("detector"),
                "confidence": entity.get("confidence"),
                "action": entity.get("action"),
                "identifier": entity.get("identifier"),
                "start": entity.get("start") if isinstance(entity.get("start"), int) else (entity.get("span")[0] if isinstance(entity.get("span"), (list, tuple)) else None),
                "end": entity.get("end") if isinstance(entity.get("end"), int) else (entity.get("span")[1] if isinstance(entity.get("span"), (list, tuple)) else None),
            }
            for entity in (result.get("entities") or [])
        ],
        "user_agent": request.headers.get("User-Agent"),
    })

    event = {
        "event": "scrub",
        "operation_id": result.get("operation_id"),
        "actor": _default_actor("system"),
        "client": _client_meta(request),
        "source": {
            "type": "text",
            "path": None,
            "filename": req.filename,
            "mime": "text/plain",
            "bytes": len(req.text.encode("utf-8")),
        },
        "policy": {"clearance": req.c_level, "matrix_version": "v1"},
        "counts": _entity_counts(result.get("entities", []), req.c_level),
        "hashes": _hashes_payload(
            original_hash=result.get("original_hash"),
            scrubbed_text=result.get("scrubbed"),
            receipt_path=result.get("receipt_path"),
        ),
        "receipt_path": result.get("receipt_path"),
    }
    _emit_audit_event(event)

    return ScrubResponse.model_validate(result)


@app.post("/descrub")
def api_descrub(req: DescrubRequest, request: Request):
    allowed = {r.strip().lower() for r in os.environ.get("SECUREPROMPT_DESCRUB_ROLES", "admin,reviewer").split(",")}
    role = (
        (request.headers.get("X-Role") or getattr(req, "role", "") or "")
        .strip()
        .lower()
    )
    if role not in allowed:
        _emit_audit_event(
            {
                "event": "descrub",
                "operation_id": req.operation_id,
                "actor": _default_actor(role or "user"),
                "client": _client_meta(request),
                "source": {
                    "type": "vault",
                    "path": None,
                    "filename": None,
                    "mime": "application/json",
                    "bytes": 0,
                },
                "policy": {"clearance": "C3", "matrix_version": "v1"},
                "counts": _entity_counts([], "C3"),
                "hashes": _hashes_payload(original_hash=None, scrubbed_text=None, receipt_path=None),
                "receipt_path": None,
                "status": "denied",
            }
        )
        raise HTTPException(status_code=422, detail="Forbidden: role not allowed")

    justification = (req.justification or "").strip()
    if not justification:
        justification = (request.headers.get("X-Justification") or "").strip()
    if not justification:
        justification = "legacy-request"

    try:
        text, ctx = _descrub(req.operation_id, req.identifiers)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Receipt not found")

    AUDIT.append({
        "actor": request.headers.get("X-Actor") or "api",
        "endpoint": "/descrub",
        "client_ip": request.client.host if request.client else None,
        "operation_id": req.operation_id,
        "identifiers": req.identifiers,
        "restored": ctx.get("restored"),
        "justification": justification,
        "role": role,
    })

    _emit_audit_event(
        {
            "event": "descrub",
            "operation_id": req.operation_id,
            "actor": _default_actor(role or "user"),
            "client": _client_meta(request),
            "source": {
                "type": "vault",
                "path": None,
                "filename": None,
                "mime": "application/json",
                "bytes": 0,
            },
            "policy": {"clearance": "C3", "matrix_version": "v1"},
            "counts": _entity_counts([], "C3"),
            "hashes": _hashes_payload(original_hash=None, scrubbed_text=None, receipt_path=None),
            "receipt_path": None,
            "status": "approved",
            "restored": ctx.get("restored"),
            "justification": justification,
        }
    )

    return {
        "operation_id": req.operation_id,
        "restored": ctx.get("restored"),
        "descrubbed": text,
    }


# --- Metrics summary endpoint (additive) --------------------------------------
try:
    from secureprompt.audit.metrics import summarize_metrics as _sp_summarize_metrics  # type: ignore
except Exception:
    _sp_summarize_metrics = None  # type: ignore


@app.get("/metrics")
def api_metrics():
    if _sp_summarize_metrics is None:
        return {
            "receipts": 0,
            "entities": 0,
            "by_label": {},
            "by_action": {},
            "by_action_no_unknown": {},
            "latency_ms": {"p50": 0, "p90": 0},
        }
    return _sp_summarize_metrics()
# -----------------------------------------------------------------------------#


# --- Human Audit page ---------------------------------------------------------
DEBUG = bool(int(os.environ.get("DEBUG", "0")))


def _templates_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "secureprompt" / "ui" / "templates"


def _load_templates() -> Jinja2Templates:
    tpl_dir = _templates_dir()
    if not tpl_dir.exists():
        tpl_dir.mkdir(parents=True, exist_ok=True)

    tmpls = Jinja2Templates(directory=str(tpl_dir))

    if DEBUG:
        try:
            tmpls.env.auto_reload = True
        except Exception:
            pass
        try:
            tmpls.env.cache.clear()
        except Exception:
            pass
        try:
            tmpls.env.cache = {}
        except Exception:
            pass
        try:
            tmpls.env.undefined = jinja2.DebugUndefined
        except Exception:
            pass

    print(f"Templates dir: {tpl_dir}")
    return tmpls


templates = _load_templates()


@app.get("/ui/audit", response_class=HTMLResponse)
async def ui_audit(request: Request):
    roles = ALLOWED_DESCRUB_ROLES or ["auditor"]
    resp = templates.TemplateResponse("audit.html", {"request": request, "descrub_roles": roles})
    if DEBUG:
        resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


@app.get("/ui/metrics", response_class=HTMLResponse)
async def ui_metrics(request: Request):
    resp = templates.TemplateResponse("metrics.html", {"request": request})
    if DEBUG:
        resp.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


@app.post("/files/redact-text", response_model=ScrubWithFileResponse)
def api_redact_text(request: Request, req: ScrubRequest = Body(...)) -> ScrubWithFileResponse:
    result = scrub_text(req.text, req.c_level)
    _maybe_store_original(result.get("receipt_path"), text=req.text)
    if write_redacted_text is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="File writer unavailable")

    filename = req.filename or "scrubbed.txt"
    target = REDACTED_DIR / filename
    output_path = write_redacted_text(result["scrubbed"], source_path=target)

    event = {
        "event": "file_scrub",
        "operation_id": result.get("operation_id"),
        "actor": _default_actor("system"),
        "client": _client_meta(request),
        "source": {
            "type": "text",
            "path": str(target),
            "filename": filename,
            "mime": "text/plain",
            "bytes": len(req.text.encode("utf-8")),
        },
        "policy": {"clearance": req.c_level, "matrix_version": "v1"},
        "counts": _entity_counts(result.get("entities", []), req.c_level),
        "hashes": _hashes_payload(
            original_hash=result.get("original_hash"),
            scrubbed_text=result.get("scrubbed"),
            receipt_path=result.get("receipt_path"),
        ),
        "receipt_path": result.get("receipt_path"),
        "redacted_path": str(output_path),
    }
    _emit_audit_event(event)

    payload = dict(result)
    payload["output_path"] = str(output_path)
    return ScrubWithFileResponse.model_validate(payload)


@app.post("/descrub", response_model=DescrubResponse)

def api_descrub(request: Request, req: DescrubRequest = Body(...)) -> DescrubResponse:
    role = (req.role or "").lower()
    clearance = (req.clearance or "C3").upper()
    ref = req.receipt_path or req.operation_id

    role = (role or "").strip().lower()
    if role not in ALLOWED_DESCRUB_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="role not permitted to de-scrub")

    if role not in ACTIONS_ALLOW:
        event = {
            "event": "descrub",
            "operation_id": ref,
            "actor": _default_actor(role or "user"),
            "client": _client_meta(request),
            "source": {
                "type": "receipt",
                "path": req.receipt_path,
                "filename": Path(req.receipt_path).name if req.receipt_path else None,
                "mime": "application/json",
                "bytes": _file_size(req.receipt_path),
            },
            "policy": {"clearance": clearance, "matrix_version": "v1"},
            "counts": _entity_counts([], clearance),
            "hashes": _hashes_payload(original_hash=None, scrubbed_text=None, receipt_path=req.receipt_path),
            "receipt_path": req.receipt_path,
            "status": "denied",
        }
        _emit_audit_event(event)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="role not permitted")

    if not ref:
        event = {
            "event": "descrub",
            "operation_id": None,
            "actor": _default_actor(role or "user"),
            "client": _client_meta(request),
            "source": {
                "type": "receipt",
                "path": None,
                "filename": None,
                "mime": "application/json",
                "bytes": 0,
            },
            "policy": {"clearance": clearance, "matrix_version": "v1"},
            "counts": _entity_counts([], clearance),
            "hashes": _hashes_payload(original_hash=None, scrubbed_text=None, receipt_path=None),
            "receipt_path": None,
            "status": "invalid_request",
        }
        _emit_audit_event(event)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="provide operation_id or receipt_path")

    try:
        receipt = read_receipt(ref)
    except FileNotFoundError as exc:  # pragma: no cover - defensive
        event = {
            "event": "descrub",
            "operation_id": ref,
            "actor": _default_actor(role or "user"),
            "client": _client_meta(request),
            "source": {
                "type": "receipt",
                "path": req.receipt_path,
                "filename": Path(req.receipt_path).name if req.receipt_path else None,
                "mime": "application/json",
                "bytes": _file_size(req.receipt_path),
            },
            "policy": {"clearance": clearance, "matrix_version": "v1"},
            "counts": _entity_counts([], clearance),
            "hashes": _hashes_payload(original_hash=None, scrubbed_text=None, receipt_path=req.receipt_path),
            "receipt_path": req.receipt_path,
            "status": "not_found",
        }
        _emit_audit_event(event)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    scrubbed = req.text or (receipt.get("scrubbed") or {}).get("text")
    if not scrubbed:
        event = {
            "event": "descrub",
            "operation_id": receipt.get("operation_id"),
            "actor": _default_actor(role or "user"),
            "client": _client_meta(request),
            "source": {
                "type": "receipt",
                "path": receipt.get("receipt_path"),
                "filename": Path(receipt.get("receipt_path") or "").name if receipt.get("receipt_path") else None,
                "mime": "application/json",
                "bytes": _file_size(receipt.get("receipt_path")),
            },
            "policy": {"clearance": clearance, "matrix_version": "v1"},
            "counts": _entity_counts([], clearance),
            "hashes": _hashes_payload(original_hash=None, scrubbed_text=None, receipt_path=receipt.get("receipt_path")),
            "receipt_path": receipt.get("receipt_path"),
            "status": "invalid_payload",
        }
        _emit_audit_event(event)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="scrubbed text not provided and not stored in receipt",
        )

    descrubbed = descrub_text(
        scrubbed_text=scrubbed,
        receipt=receipt,
        clearance=clearance,
        ids=req.ids,
    )

    receipt_path = receipt.get("receipt_path")
    receipt_hashes = (receipt.get("hashes") or {})

    event = {
        "event": "descrub",
        "operation_id": receipt.get("operation_id"),
        "actor": _default_actor(role or "user"),
        "client": _client_meta(request),
        "source": {
            "type": "receipt",
            "path": receipt_path,
            "filename": Path(receipt_path or "").name if receipt_path else None,
            "mime": "application/json",
            "bytes": _file_size(receipt_path),
        },
        "policy": {"clearance": clearance, "matrix_version": "v1"},
        "counts": _entity_counts(receipt.get("entities", []), clearance),
        "hashes": _hashes_payload(
            original_hash=receipt_hashes.get("original"),
            scrubbed_text=receipt.get("scrubbed", {}).get("text"),
            receipt_path=receipt_path,
        ),
        "receipt_path": receipt_path,
        "restored_ids": len(req.ids or []),
        "status": "approved",
    }
    _emit_audit_event(event)

    return DescrubResponse(descrubbed=descrubbed, operation_id=receipt.get("operation_id"))



@app.get("/", response_class=HTMLResponse)
async def ui_dashboard(request: Request, clearance: Optional[str] = None) -> HTMLResponse:
    selected = (clearance or request.query_params.get("clearance") or "C3").upper()
    if selected not in CLEARANCE_OPTIONS:
        selected = "C3"
    return _render_dashboard(request, clearance=selected)


@app.post("/ui/scrub", response_class=HTMLResponse)
async def ui_scrub(
    request: Request,
    clearance: str = Form("C3"),
    text: str = Form(""),
    upload: Optional[UploadFile] = File(None),
) -> HTMLResponse:
    clearance = clearance.upper() if clearance else "C3"
    if clearance not in CLEARANCE_OPTIONS:
        clearance = "C3"

    upload_max_mb = _scrub_upload_max_mb()
    max_bytes = upload_max_mb * 1024 * 1024
    workbook_allowed = _scrub_workbook_allowed()
    default_c_level = _scrub_default_c_level()
    keep_original = _env_bool("KEEP_ORIGINAL_IN_RECEIPTS", False)
    examples = _scrub_examples()

    error: Optional[str] = None
    original_text = text or ""
    saved_path_display: Optional[str] = None
    saved_href: Optional[str] = None
    file_name = upload.filename if upload and upload.filename else None
    entities_raw: List[Dict[str, Any]] = []
    operation_id: Optional[str] = None
    receipt_path: Optional[str] = None
    sanitized: Optional[str] = None
    is_xlsx = False
    original_hash: Optional[str] = None
    scrubbed_for_hash: Optional[str] = None
    source_type = "text"
    source_mime = "text/plain"
    source_path: Optional[str] = None
    source_bytes = len(original_text.encode("utf-8")) if original_text else 0

    try:
        if upload is not None and upload.filename:
            suffix = Path(upload.filename).suffix.lower()
            if suffix == ".xlsx":
                if not workbook_allowed:
                    raise ValueError("Workbook uploads are disabled")
                is_xlsx = True
                temp_path = await _save_upload_to_tempfile(upload, max_bytes=max_bytes)
                try:
                    workbook = scrub_workbook(temp_path, clearance, filename=file_name)
                finally:
                    temp_path.unlink(missing_ok=True)
                original_text = workbook["original_display"]
                sanitized = workbook["sanitized_display"]
                entities_raw = workbook["entities"]
                operation_id = workbook["operation_id"]
                receipt_path = workbook["receipt_path"]
                _maybe_store_original(receipt_path, text=original_text)
                redacted_path = Path(workbook["redacted_path"])
                saved_path_display = redacted_path.name
                saved_href = f"/redacted/{operation_id}/{redacted_path.name}"
                original_hash = workbook.get("original_hash")
                scrubbed_for_hash = workbook.get("scrubbed_text")
                source_bytes = workbook.get("source_bytes", 0)
                source_type = "file"
                source_mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                source_path = str(redacted_path)
            else:
                original_text = await _ingest_upload(upload, max_bytes=max_bytes)
                source_type = "file"
                if suffix in {".txt", ".text", ".csv", ".html", ".htm"}:
                    source_mime = "text/plain"
                elif suffix == ".pdf":
                    source_mime = "application/pdf"
                elif suffix == ".png":
                    source_mime = "image/png"
                source_bytes = len(original_text.encode("utf-8")) if original_text else 0
        elif not original_text.strip():
            error = "Provide text or upload a supported file."
    except ValueError as exc:
        error = str(exc)
    except RuntimeError as exc:
        error = str(exc)

    if error is not None:
        error_event = {
            "event": "error",
            "operation_id": None,
            "actor": _default_actor("user"),
            "client": _client_meta(request),
            "source": {
                "type": "file" if file_name else "text",
                "path": None,
                "filename": file_name,
                "mime": None,
                "bytes": 0,
            },
            "policy": {"clearance": clearance, "matrix_version": "v1"},
            "counts": {"entities_total": 0, "masked": 0, "by_label": {}, "by_c_level": {}},
            "hashes": _hashes_payload(original_hash=None, scrubbed_text=None, receipt_path=None),
            "receipt_path": None,
            "message": error,
        }
        _emit_audit_event(error_event)
        if error == "Upload exceeds size limit":
            error = f"Upload exceeds {upload_max_mb} MB limit."
        context = _scrub_context(
            request,
            clearance,
            upload_max_mb=upload_max_mb,
            workbook_allowed=workbook_allowed,
            default_c_level=default_c_level,
            keep_original=keep_original,
            examples=examples,
            original_text=original_text,
            error=error,
        )
        return templates.TemplateResponse("scrub.html", context)

    if not is_xlsx:
        result = scrub_text(original_text, "C4")
        _maybe_store_original(result.get("receipt_path"), text=original_text)
        entities_raw = result.get("entities", [])
        result["scrubbed_mask"] = result.get("scrubbed") or ""
        result["scrubbed_tokens"] = _combine_and_tokenize(original_text or "", entities_raw)
        result["scrubbed"] = result["scrubbed_tokens"]
        sanitized = result["scrubbed"]

        if file_name and Path(file_name).suffix.lower() in TEXT_EXTENSIONS and write_redacted_text is not None:
            target = REDACTED_DIR / file_name
            saved_file = write_redacted_text(sanitized, source_path=target)
            saved_path_display = Path(saved_file).name
            saved_href = f"/files/{Path(saved_file).name}"
            source_path = str(saved_file)
            source_type = "file"
            source_mime = "text/plain"

        operation_id = result.get("operation_id")
        receipt_path = result.get("receipt_path")
        original_hash = result.get("original_hash")
        scrubbed_for_hash = result.get("scrubbed")
        source_bytes = len(original_text.encode("utf-8")) if original_text else 0

    for ent in entities_raw or []:
        _ensure_entity_value(ent, original_text or "")

    counts = _entity_counts(entities_raw, clearance)
    hashes = _hashes_payload(
        original_hash=original_hash,
        scrubbed_text=scrubbed_for_hash,
        receipt_path=receipt_path,
    )

    baseline_ctx = _baseline_context(file_name=file_name, clearance=clearance, entities=entities_raw)

    entities_view, entity_counts_view = _format_entities_for_view(entities_raw)

    event = {
        "event": "ui_scrub",
        "operation_id": operation_id,
        "actor": _default_actor("user"),
        "client": _client_meta(request),
        "source": {
            "type": source_type,
            "path": source_path,
            "filename": file_name,
            "mime": source_mime,
            "bytes": source_bytes,
        },
        "policy": {"clearance": clearance, "matrix_version": "v1"},
        "counts": counts,
        "hashes": hashes,
        "receipt_path": receipt_path,
    }
    _emit_audit_event(event)

    audit_url = f"/ui/audit?highlight={operation_id}" if operation_id else None
    context = _scrub_context(
        request,
        clearance,
        upload_max_mb=upload_max_mb,
        workbook_allowed=workbook_allowed,
        default_c_level=default_c_level,
        keep_original=keep_original,
        examples=examples,
        original_text=original_text,
        sanitized_text=sanitized or "",
        entities=entities_view,
        entity_counts=entity_counts_view,
        operation_id=operation_id,
        receipt_path=receipt_path,
        audit_url=audit_url,
        counts=counts,
        hashes=hashes,
        saved_href=saved_href,
        saved_path=saved_path_display,
        baseline_ctx=baseline_ctx,
    )
    return templates.TemplateResponse("scrub.html", context)


@app.get("/ui/scrub", response_class=HTMLResponse)
async def ui_scrub_get(request: Request, clearance: str = "C3") -> HTMLResponse:
    selected = (clearance or "C3").upper()
    if selected not in CLEARANCE_OPTIONS:
        selected = "C3"
    try:
        context = _scrub_context(request, selected)
        return templates.TemplateResponse("scrub.html", context)
    except Exception:
        logger.exception("scrub ui render failed")
        raise



@app.get("/audit")
def audit_list(offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000)):
    """Return a paginated slice of the append-only audit chain."""
    return {"offset": offset, "limit": limit, "items": AUDIT.stream(offset=offset, limit=limit)}


@app.get("/audit/jsonl")
def audit_jsonl():
    """Stream the raw JSONL audit file."""
    return StreamingResponse(io.BytesIO(AUDIT.as_bytes()), media_type="application/x-ndjson")

# --- BEGIN: favicon hotfix (append-only) ---
from starlette.responses import Response

_logger = logging.getLogger("secureprompt.favicon")

def _has_favicon_route(_app) -> bool:
    try:
        return any(getattr(r, "path", None) == "/favicon.ico" for r in _app.router.routes)
    except Exception:
        return False

try:
    # `app` must already exist by this point in the file
    _app = globals().get("app")
    if _app is not None and not _has_favicon_route(_app):
        @_app.get("/favicon.ico", include_in_schema=False)
        async def _favicon() -> Response:  # type: ignore[no-redef]
            # Empty but valid ICO response (200) to satisfy browsers/devtools
            return Response(content=b"", media_type="image/x-icon",
                            headers={"Cache-Control": "public, max-age=86400"})
        _logger.info("Registered /favicon.ico route (200 image/x-icon).")
    elif _app is None:
        _logger.warning("No global `app` found; favicon hotfix skipped.")
    else:
        _logger.info("/favicon.ico already present; hotfix skipped.")
except Exception as _e:
    _logger.exception("Favicon hotfix failed: %s", _e)
# --- END: favicon hotfix (append-only) ---
# --- BEGIN: favicon route (idempotent, GET+HEAD) ---
from starlette.responses import Response

def _route_exists(_app, path: str) -> bool:
    try:
        return any(getattr(r, "path", None) == path for r in _app.router.routes)
    except Exception:
        return False

_app = globals().get("app")
if _app is not None and not _route_exists(_app, "/favicon.ico"):
    @_app.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
    async def _favicon():
        # Return a valid (empty) ICO with 200 OK. Cached for a day.
        return Response(
            content=b"",
            media_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=86400"},
        )
# --- END: favicon route ---# --- BEGIN: favicon shim (idempotent) ---
try:
    from fastapi import Response
    _has_favicon = any(getattr(r, "path", "") == "/favicon.ico" for r in getattr(app, "routes", []))
    if not _has_favicon:
        @app.get("/favicon.ico")
        async def _favicon_get() -> Response:
            # Return 200 with icon content-type; body can be empty (browsers cope fine)
            return Response(content=b"", media_type="image/x-icon", headers={"Cache-Control": "public, max-age=86400"})

        @app.head("/favicon.ico")
        async def _favicon_head() -> Response:
            return Response(content=b"", media_type="image/x-icon", headers={"Cache-Control": "public, max-age=86400"})
except Exception:
    # Non-fatal if app is not yet defined in this module context
    pass
# --- END: favicon shim (idempotent) ---
from fastapi.responses import HTMLResponse
