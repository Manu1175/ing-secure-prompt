from fastapi import FastAPI, HTTPException
from httpcore import request
from pydantic import BaseModel
from src.scrubber import Scrubber
from src.audit import AuditLogger
from src.classifier import Classifier
from src.descrubber import DeScrubber, AccessControlPolicy
import os
from typing import List, Dict, Optional
from dotenv import load_dotenv
# from openai import OpenAI
import google.generativeai as genai
import yaml
from mistralai import Mistral
import re
import json

app = FastAPI(title="SecurePrompt")

# ----- Paths -----
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datasets")
rules_yaml = os.path.join(BASE_DIR, "updated_ruleset.yaml")
datasets_path = os.path.join(BASE_DIR, "*.xlsx")
whitelist_yaml = os.path.join(BASE_DIR, "whitelist.yaml")
audit_log_path = os.path.join(BASE_DIR, "audit.log")

# ----- Initialize components -----
audit_logger = AuditLogger(audit_log_path)

access_policy = AccessControlPolicy()

descrubber = DeScrubber(audit_logger=audit_logger, access_policy=access_policy)

scrubber = Scrubber(rules_yaml=rules_yaml, whitelist_yaml=whitelist_yaml, descrubber=descrubber)
# Connect scrubber and descrubber (share vault)
descrubber.vault.load_from_mapping(scrubber.mapping)

# Optional NER: set to None if no model available
# ner_model_path = None
ner_model_path = "dbmdz/bert-large-cased-finetuned-conll03-english"
# Example Hugging Face NER model:
# ner_model_path = "dbmdz/bert-large-cased-finetuned-conll03-english"
classifier = Classifier(ner_model_path=ner_model_path, rules_yaml=rules_yaml)


# ----- Load environment variables -----
load_dotenv()  
# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
# model = genai.GenerativeModel("gemini-1.5-pro")
# mistral_client = Mistral(api_key=os.getenv("MISTRAL_API_KEY"))
# model_name = "mistral-large-latest"
# ollama_client = Ollama()  # Local LLM; Ollama runs locally, no API key needed
# model_name = "gemma3:1b"  # Adjust to the model you have installed
# ollama_client = Client()
# GROQ_API_KEY = os.getenv("GROQ_API_KEY")
# if not GROQ_API_KEY:
#    raise RuntimeError("Set environment variable GROQ_API_KEY")


# Configure API key
# GENIE_API_KEY = os.getenv("GOOGLE_API_KEY")
# if not GENIE_API_KEY:
#   raise RuntimeError("Set environment variable GOOGLE_API_KEY")
# genai.configure(api_key=GENIE_API_KEY)

# Initialize Gemini LLM
# llm_model = genai.GenerativeModel("gemini-1.5")  # or "gemini-1.5-pro"

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

# Initialize OpenAI client with .env key
# client = OpenAI(api_key=OPENAI_API_KEY)

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
    placeholders: List[str]
    user_id: str
    user_role: str               # <-- NEW (for access control)
    justification: str

class DeScrubResponse(BaseModel):
    descrubbed_prompt: str
    restored_entities: List[Dict]
    denied_entities: Optional[List[Dict]] = []  # <-- NEW
    audit_id: str

class LLMRequest(BaseModel):
    scrubbed_prompt: str
    user_id: str

class LLMResponse(BaseModel):
    llm_response: str
    audit_id: str

# Load YAML ruleset once at startup
with open(rules_yaml, "r") as f:
    data = yaml.safe_load(f)

if not data or "rules" not in data:
    raise ValueError("YAML file is empty or missing 'rules' key")

rules = data["rules"]

placeholder_context = {}
for rule in rules:
    placeholder = rule.get("placeholder")
    column_name = rule.get("column")
    if placeholder:
        placeholder_context[placeholder] = f"{column_name} value"


# ----- Helper functions
def scrub_text_for_llm(prompt: str, user_id: str) -> ScrubbedResponse:
    """Scrubs sensitive text before sending to the LLM."""
    entities = classifier.classify(prompt)
    entities = [e for e in entities if e["value"] not in scrubber.whitelist]

    scrubbed_text, enriched_entities = scrubber.scrub_text(prompt, entities)

    audit_id = audit_logger.log_action(
        user_id=user_id,
        original=prompt,
        scrubbed=scrubbed_text,
        entities=enriched_entities
    )

    return ScrubbedResponse(
        scrubbed_prompt=scrubbed_text,
        entities=enriched_entities,
        audit_id=audit_id
    )
   
def build_placeholder_context(rules: list) -> str:
    """Generate a natural-language explanation of placeholders for the LLM."""
    context_lines = [
        "You will receive a prompt where sensitive information has been replaced with placeholders enclosed in double braces (e.g., {{TERM}}).",
        "Each placeholder corresponds to a specific data field or concept. Interpret them as if they contain real values.",
        "",
        "Here is the placeholder mapping:"
    ]

    for rule in rules:
        placeholder = rule.get("placeholder")
        column = rule.get("column")
        classification = rule.get("recommended_classification", "")
        if placeholder and column:
            context_lines.append(f" - {placeholder}: represents a '{column}' ({classification} classification).")

    context_lines.append(
        "\nWhen generating your response, use these placeholders as meaningful stand-ins for real data values."
    )

    return "\n".join(context_lines)

# Helper: get last scrubbed value from audit.log
def get_last_scrubbed_value(placeholder_id: str, scrubbed_prompt: str, log_file="./datasets/audit.log"):
    try:
        with open(log_file, "r") as f:
            for line in reversed(list(f)):
                record = json.loads(line)
                if record.get("event") == "action" and "scrubbed" in record:
                    if record["scrubbed"] == scrubbed_prompt:
                        for entity in record.get("entities", []):
                            if entity["id"] == placeholder_id:
                                return entity["value"]
    except FileNotFoundError:
        pass
    return None

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
    
    # After scrubbing, sync entities into the shared descrubber vault
    print("[DEBUG] Stored mapping keys in scrubber:")
    print(list(scrubber.mapping.keys()))

    for placeholder, value in scrubber.mapping.items():
        descrubber.vault.store(placeholder, value)  # store the full key-value pair

    print("[DEBUG] Shared vault now contains:")
    print(descrubber.vault.all_keys())

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
    """
    De-scrub endpoint using in-memory vault and audit logging fallback
    """
    try:
        restored_entities = []
        denied_entities = []
        descrubbed_text = request.scrubbed_prompt

        for ph in request.placeholders:
            record = descrubber.mapping.get(ph)  # check in-memory vault
            if record:
                value = record["value"]
            else:
                # fallback to audit log
                value = get_last_scrubbed_value(ph, request.scrubbed_prompt)

            if value:
                descrubbed_text = descrubbed_text.replace(ph, value)
                restored_entities.append({
                    "placeholder_id": ph,
                    "value": value,
                    "entity": record["entity"] if record else "Unknown",
                    "confidence": record["confidence"] if record else None
                })
            else:
                denied_entities.append({
                    "placeholder_id": ph,
                    "reason": "Placeholder not found in vault or audit log"
                })

        # log the de-scrub action
        audit_id = audit_logger.log_descrub(
            user_id=request.user_id,
            restored_text=descrubbed_text,
            restored_entities=restored_entities,
            justification=request.justification
        )

        return DeScrubResponse(
            descrubbed_prompt=descrubbed_text,
            restored_entities=restored_entities,
            denied_entities=denied_entities,
            audit_id=audit_id
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"De-scrubbing failed: {str(e)}")
    
@app.post("/ask-llm", response_model=LLMResponse)
async def ask_llm(request_data: LLMRequest):
    # 1️⃣ Scrub input
    scrubbed = scrub_text_for_llm(
        prompt=request_data.scrubbed_prompt,
        user_id=request_data.user_id
    )

    # 2️⃣ Send to Gemini
    model = genai.GenerativeModel("gemini-2.5-flash")
    # response = model.generate_content(scrubbed.scrubbed_prompt)
    # Dynamically build placeholder context from YAML rules
    context = build_placeholder_context(rules)

    # Combine context + scrubbed prompt
    # full_prompt = f"{context}\n\nUser Prompt:\n{scrubbed.scrubbed_prompt}"

    # response = model.generate_content(full_prompt)
    
    # Build context from YAML
    context = build_placeholder_context(rules)

    # System instruction to guide Gemini
    system_role = (
        "You are an intelligent process documentation assistant. "
        "You receive user prompts where sensitive values are replaced with placeholders "
        "like {{TERM}} or <PROCESS_NAME>. Each placeholder represents a real concept or field. "
        "Your job is to generate a well-structured, natural-language response that uses "
        "the placeholders meaningfully (not literally). Do NOT repeat placeholders verbatim "
        "unless they belong in a labeled field or title. Instead, explain what they represent "
        "or integrate them naturally into the response."
    )

    # Combine everything into a clean final prompt
    full_prompt = f"""{system_role}

    {context}

    User Prompt:
    {scrubbed.scrubbed_prompt}

    Now write the complete response text as if the placeholders contain real values.
    """

    response = model.generate_content(full_prompt)

    # 3️⃣ Extract model output
    llm_output = response.text if hasattr(response, "text") else str(response)

    # 4️⃣ Log the interaction
    audit_id = audit_logger.log_action(
        user_id=request_data.user_id,
        original=request_data.scrubbed_prompt,
        scrubbed=scrubbed.scrubbed_prompt,
        entities=[e.model_dump() for e in scrubbed.entities],
        action="llm_response"
    )

    # 5️⃣ Return the response
    return LLMResponse(
        llm_response=llm_output,
        audit_id=audit_id
    )
