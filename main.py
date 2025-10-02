from fastapi import FastAPI
from pydantic import BaseModel
from src.scrubber import Scrubber
from src.audit import AuditLogger
from src.classifier import Classifier
import os
from typing import List, Dict

app = FastAPI(title="SecurePrompt")

# ----- Paths -----
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datasets")
rules_yaml = os.path.join(BASE_DIR, "updated_ruleset.yaml")
datasets_path = os.path.join(BASE_DIR, "*.xls")
whitelist_yaml = os.path.join(BASE_DIR, "whitelist.yaml")
audit_log_path = os.path.join(BASE_DIR, "audit.log")

# ----- Initialize components -----
scrubber = Scrubber(rules_yaml=rules_yaml, whitelist_yaml=whitelist_yaml)

# Optional NER: set to None if no model available
# ner_model_path = None
ner_model_path = "dbmdz/bert-large-cased-finetuned-conll03-english"
# Example Hugging Face NER model:
# ner_model_path = "dbmdz/bert-large-cased-finetuned-conll03-english"

classifier = Classifier(ner_model_path=ner_model_path, rules_yaml=rules_yaml)

audit_logger = AuditLogger(audit_log_path)

# ----- Models -----
class PromptRequest(BaseModel):
    prompt: str
    user_id: str

class EntityResponse(BaseModel):
    id: str
    entity: str
    value: str
    recommended_classification: str
    confidence: float
    explanation: str

class ScrubbedResponse(BaseModel):
    scrubbed_prompt: str
    entities: List[EntityResponse]
    audit_id: str

class DeScrubRequest(BaseModel):
    scrubbed_prompt: str
    placeholders: list[str]
    user_id: str
    justification: str

class DeScrubResponse(BaseModel):
    descrubbed_prompt: str
    restored_entities: list
    audit_id: str

# ----- Root endpoint -----
@app.get("/")
def root():
    return {"message": "SecurePrompt API is running"}

# ----- Scrub endpoint -----
@app.post("/scrub/prompt", response_model=ScrubbedResponse)
def scrub_prompt(request: PromptRequest):
    # 1️⃣ Detect entities (regex + keywords + optional NER)
    entities = classifier.classify(request.prompt)

    # Filter whitelist early
    entities = [e for e in entities if e["value"] not in scrubber.whitelist]

    # 2️⃣ Deduplicate by value (keep highest confidence)
    seen_values = set()
    unique_entities = []
    for e in sorted(entities, key=lambda x: x.get("confidence", 0), reverse=True):
        if e["value"] not in seen_values:
            unique_entities.append(e)
            seen_values.add(e["value"])

    # 3️⃣ Scrub text using YAML placeholders
    scrubbed_text, enriched_entities = scrubber.scrub_text(
        request.prompt, unique_entities
    )

    # 4️⃣ Log audit action (handles numeric confidences safely)
    audit_id = audit_logger.log_action(
        user_id=request.user_id,
        original=request.prompt,
        scrubbed=scrubbed_text,
        entities=enriched_entities
    )

    return ScrubbedResponse(
        scrubbed_prompt=scrubbed_text,
        entities=enriched_entities,
        audit_id=audit_id
    )

# ----- Descrub endpoint -----
@app.post("/descrub/prompt", response_model=DeScrubResponse)
def descrub_prompt(request: DeScrubRequest):
    restored_entities = []
    descrubbed_text = request.scrubbed_prompt

    for ph in request.placeholders:
        if ph in scrubber.mapping:
            original = scrubber.mapping[ph]["value"]
            descrubbed_text = descrubbed_text.replace(ph, original, 1)
            restored_entities.append(scrubber.mapping[ph])

    audit_id = audit_logger.log_action(
        user_id=request.user_id,
        original=request.scrubbed_prompt,
        scrubbed=descrubbed_text,
        entities=restored_entities,
        justification=request.justification,
        action="descrub"
    )

    return DeScrubResponse(
        descrubbed_prompt=descrubbed_text,
        restored_entities=restored_entities,
        audit_id=audit_id
    )
