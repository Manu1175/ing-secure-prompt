"""FastAPI application exposing SecurePrompt endpoints."""

from __future__ import annotations

import hashlib
import os
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from secureprompt.audit.log import AuditLog
from secureprompt.scrub.pipeline import scrub_text


app = FastAPI(title="SecurePrompt API", version="0.0.1")


class ScrubIn(BaseModel):
    """Request payload for ``/scrub``."""

    text: str
    c_level: str = "C3"


class DescrubIn(BaseModel):
    """Request payload for selective de-scrubbing."""

    ids: List[str]
    justification: str
    role: str


ALLOWED_ROLES = {"admin", "auditor"}
AUDIT_LOG = AuditLog(os.environ.get("SECUREPROMPT_AUDIT_PATH", "data/audit.log"))


@app.get("/", include_in_schema=False)
def root():
    """Redirect ``/`` to the interactive API docs."""

    return RedirectResponse(url="/docs")


@app.get("/healthz")
def healthz():
    """Kubernetes-friendly health probe."""

    return {"ok": True}


@app.post("/scrub")
def scrub(in_: ScrubIn):
    """Scrub sensitive entities from the incoming text and audit the action."""

    result = scrub_text(in_.text, in_.c_level)

    AUDIT_LOG.append(
        {
            "action": "scrub",
            "c_level": in_.c_level,
            "input_hash": result["original_hash"],
            "scrubbed_hash": hashlib.sha256(result["scrubbed"].encode("utf-8")).hexdigest(),
            "identifiers": [entity["identifier"] for entity in result["entities"]],
        }
    )

    return result

@app.post("/files/redact-text")
def redact_text(req: ScrubRequest):
    res = scrub_text(req.text, req.c_level)
    out = write_redacted_text(req.filename or "input.txt", res["scrubbed"])
    return {"output_path": str(out), **res}

@app.post("/descrub")
def descrub(payload: DescrubIn):
    """Handle selective de-scrub requests with a simple role gate."""

    status = "approved"
    if payload.role not in ALLOWED_ROLES:
        status = "denied"
        AUDIT_LOG.append(
            {
                "action": "descrub",
                "role": payload.role,
                "justification": payload.justification,
                "requested_ids": payload.ids,
                "status": status,
            }
        )
        raise HTTPException(status_code=422, detail="role not permitted")

    AUDIT_LOG.append(
        {
            "action": "descrub",
            "role": payload.role,
            "justification": payload.justification,
            "requested_ids": payload.ids,
            "status": status,
        }
    )

    return {"ids": payload.ids, "status": status}
