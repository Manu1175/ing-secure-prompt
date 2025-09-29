from fastapi import FastAPI
from pydantic import BaseModel
from secureprompt.scrub.pipeline import scrub_text

app = FastAPI()

class ScrubIn(BaseModel):
    text: str
    c_level: str = "C3"

@app.post("/scrub")
def scrub(in_: ScrubIn):
    return scrub_text(in_.text, in_.c_level)
