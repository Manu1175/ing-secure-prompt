"""FastAPI entry point for SecurePrompt UI and JSON APIs."""

from __future__ import annotations

import json
import os
import tempfile
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    Body,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from secureprompt.scrub.pipeline import scrub_text
from secureprompt.ui.selective import selective_sanitize
from secureprompt.receipts.store import read_receipt
from secureprompt.receipts.descrub import descrub_text

from secureprompt.files.text import load_text
from secureprompt.files.pdf import extract_pdf_text
from secureprompt.files.ocr import ocr_image_to_text

try:  # pragma: no cover - optional helper
    from secureprompt.files.redact import write_redacted_text
except Exception:  # pragma: no cover - degrade gracefully
    write_redacted_text = None  # type: ignore[attr-defined]

REDACTED_DIR = Path("data/out")
REDACTED_DIR.mkdir(parents=True, exist_ok=True)

ACTIONS_ALLOW = {"admin", "auditor"}
CLEARANCE_OPTIONS = ("C1", "C2", "C3", "C4")
TEXT_EXTENSIONS = {".txt", ".text", ".html", ".htm", ".csv"}
ALLOWED_EXTENSIONS = TEXT_EXTENSIONS | {".pdf", ".png"}

templates = Jinja2Templates(directory="templates")

AUDIT_PATH = Path(os.environ.get("SECUREPROMPT_AUDIT_PATH", "data/audit.log"))

try:  # pragma: no cover - if audit logger missing we fall back to plain file appends
    from secureprompt.audit.log import AuditLog

    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _audit = AuditLog(str(AUDIT_PATH))
except Exception:  # pragma: no cover
    _audit = None  # type: ignore[assignment]


class ScrubRequest(BaseModel):
    text: str
    c_level: str = "C3"
    filename: Optional[str] = None


class ScrubResponse(BaseModel):
    original_hash: str
    scrubbed: str
    entities: List[Dict[str, Any]]
    operation_id: str
    receipt_path: str


class ScrubWithFileResponse(ScrubResponse):
    output_path: str


class DescrubRequest(BaseModel):
    text: Optional[str] = None
    ids: Optional[List[str]] = None
    justification: Optional[str] = None
    role: Optional[str] = None
    clearance: Optional[str] = None
    operation_id: Optional[str] = None
    receipt_path: Optional[str] = None


class DescrubResponse(BaseModel):
    descrubbed: str
    operation_id: Optional[str] = None


app = FastAPI(title="SecurePrompt", version="0.2.0")
app.mount("/files", StaticFiles(directory=REDACTED_DIR), name="files")


def _audit_append_safe(**record: Any) -> None:
    record.setdefault("ok", True)
    if _audit is not None:
        try:
            _audit.append(record)  # type: ignore[attr-defined]
            return
        except Exception:  # pragma: no cover - best effort
            pass

    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    except Exception:  # pragma: no cover - logging failure ignored
        pass


def _load_uploaded_text(path: Path, suffix: str) -> str:
    if suffix in TEXT_EXTENSIONS:
        return load_text(path)
    if suffix == ".pdf":
        return extract_pdf_text(path)
    if suffix == ".png":
        return ocr_image_to_text(str(path))
    raise ValueError(f"Unsupported file type: {suffix}")


async def _ingest_upload(upload: UploadFile) -> str:
    filename = upload.filename or "upload.txt"
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError("Unsupported file type. Allowed: .txt, .html, .csv, .pdf, .png")

    data = await upload.read()
    if not data:
        return ""

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        temp_path = Path(tmp.name)

    try:
        return _load_uploaded_text(temp_path, suffix)
    finally:
        temp_path.unlink(missing_ok=True)


def _render_dashboard(
    request: Request,
    *,
    clearance: str,
    original: Optional[str] = None,
    sanitized: Optional[str] = None,
    entities: Optional[List[Dict[str, Any]]] = None,
    error: Optional[str] = None,
    file_name: Optional[str] = None,
    saved_path: Optional[Path] = None,
    saved_href: Optional[str] = None,
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
        "saved_path": str(saved_path) if saved_path else None,
        "saved_href": saved_href,
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/scrub", response_model=ScrubResponse)
def api_scrub(req: ScrubRequest = Body(...)) -> ScrubResponse:
    result = scrub_text(req.text, req.c_level)
    _audit_append_safe(
        action="scrub",
        c_level=req.c_level,
        entity_count=len(result.get("entities", [])),
    )
    return ScrubResponse.model_validate(result)


@app.post("/files/redact-text", response_model=ScrubWithFileResponse)
def api_redact_text(req: ScrubRequest = Body(...)) -> ScrubWithFileResponse:
    result = scrub_text(req.text, req.c_level)
    if write_redacted_text is None:
        _audit_append_safe(action="scrub_file", ok=False, detail="writer unavailable")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="File writer unavailable")

    filename = req.filename or "scrubbed.txt"
    target = REDACTED_DIR / filename
    output_path = write_redacted_text(result["scrubbed"], source_path=target)
    _audit_append_safe(
        action="scrub_file",
        ok=True,
        output=str(output_path),
        c_level=req.c_level,
    )
    payload = dict(result)
    payload["output_path"] = str(output_path)
    return ScrubWithFileResponse.model_validate(payload)


@app.post("/descrub", response_model=DescrubResponse)
def api_descrub(req: DescrubRequest = Body(...)) -> DescrubResponse:
    role = (req.role or "").lower()
    if role not in ACTIONS_ALLOW:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="role not permitted")

    ref = req.receipt_path or req.operation_id
    if not ref:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="provide operation_id or receipt_path")

    try:
        receipt = read_receipt(ref)
    except FileNotFoundError as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    scrubbed = req.text or (receipt.get("scrubbed") or {}).get("text")
    if not scrubbed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="scrubbed text not provided and not stored in receipt",
        )

    clearance = (req.clearance or "C3").upper()
    descrubbed = descrub_text(
        scrubbed_text=scrubbed,
        receipt=receipt,
        clearance=clearance,
        ids=req.ids,
    )

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

    error = None
    original_text = text or ""
    saved_path: Optional[Path] = None
    saved_href: Optional[str] = None
    file_name = upload.filename if upload and upload.filename else None

    try:
        if upload is not None and upload.filename:
            original_text = await _ingest_upload(upload)
        elif not original_text.strip():
            error = "Provide text or upload a supported file."
    except ValueError as exc:
        error = str(exc)
    except RuntimeError as exc:
        error = str(exc)

    if error is not None:
        _audit_append_safe(action="ui_scrub", ok=False, clearance=clearance, file=file_name, error=error)
        return _render_dashboard(request, clearance=clearance, error=error)

    result = scrub_text(original_text, "C4")
    entities = result.get("entities", [])
    sanitized = selective_sanitize(original_text, entities, clearance)
    if sanitized == original_text and result.get("scrubbed") != original_text:
        sanitized = result["scrubbed"]

    if file_name and Path(file_name).suffix.lower() in TEXT_EXTENSIONS and write_redacted_text is not None:
        target = REDACTED_DIR / file_name
        saved_path = write_redacted_text(sanitized, source_path=target)
        saved_href = f"/files/{Path(saved_path).name}"

    _audit_append_safe(
        action="ui_scrub",
        ok=True,
        clearance=clearance,
        file=file_name,
        entities=len(entities),
    )

    return _render_dashboard(
        request,
        clearance=clearance,
        original=original_text,
        sanitized=sanitized,
        entities=entities,
        file_name=file_name,
        saved_path=saved_path,
        saved_href=saved_href,
    )


def _load_audit_records(limit: int = 200) -> List[Dict[str, Any]]:
    if not AUDIT_PATH.exists():
        return []
    records: deque[str] = deque(maxlen=limit)
    with AUDIT_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                records.append(stripped)

    output: List[Dict[str, Any]] = []
    while records:
        raw = records.pop()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"raw": raw}
        payload["short_hash"] = (payload.get("curr_hash") or "")[:8]
        output.append(payload)
    return output


@app.get("/audit", response_class=HTMLResponse)
async def audit_dashboard(request: Request) -> HTMLResponse:
    entries = _load_audit_records()
    context = {
        "request": request,
        "entries": entries,
        "has_entries": bool(entries),
        "clearance": "C3",
        "clearances": CLEARANCE_OPTIONS,
    }
    return templates.TemplateResponse("audit.html", context)
