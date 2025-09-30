from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from secureprompt.scrub.pipeline import scrub_text

app = FastAPI(title="SecurePrompt API", version="0.0.1")

class ScrubIn(BaseModel):
    text: str
    c_level: str = "C3"

# Convenience: show docs when hitting the root
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.post("/scrub")
def scrub(in_: ScrubIn):
    return scrub_text(in_.text, in_.c_level)
