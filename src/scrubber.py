import re
import pyffx
import spacy
import yaml
from collections import defaultdict
from typing import List, Dict, Tuple


class Scrubber:
    def __init__(self, rules_yaml: str, whitelist_yaml: str = None, fpe_key: str = "secure-key"):
        with open(rules_yaml) as f:
            rules_data = yaml.safe_load(f)

        self.rules = rules_data["rules"]

        # normalize + add default priority if missing
        for r in self.rules:
            r.setdefault("priority", 5)

        # sort once by priority (1 = strict, 5 = generic)
        self.rules.sort(key=lambda r: r["priority"])

        self.whitelist = set()
        if whitelist_yaml:
            with open(whitelist_yaml) as f:
                data = yaml.safe_load(f) or []
                for entry in data:
                    if isinstance(entry, dict) and entry.get("type") == "domain_term":
                        self.whitelist.add(entry.get("text", "").strip())
                    elif isinstance(entry, str):
                        self.whitelist.add(entry.strip())

        self.fpe_key = fpe_key
        self.nlp = spacy.load("en_core_web_sm")
        self.mapping = {}
        self.placeholder_counters = defaultdict(int)
        self.rules_by_entity = {r["column"]: r for r in self.rules}

        # Regexes for phone/email detection
        self.phone_regex = re.compile(
            r"(?:\+?\d{1,3})?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}"
        )
        self.email_regex = re.compile(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        )

    def fpe_encrypt(self, value: str) -> str:
        if value.isdigit() and 6 <= len(value) <= 12:
            return pyffx.String(
                self.fpe_key.encode(), alphabet="0123456789", length=len(value)
            ).encrypt(value)
        return value

    def _make_placeholder(self, entity_name: str) -> str:
        rule = self.rules_by_entity.get(entity_name)
        if rule and "placeholder" in rule:
            return rule["placeholder"]
        self.placeholder_counters[entity_name] += 1
        return f"{{{{{entity_name}_{self.placeholder_counters[entity_name]}}}}}"

    def _chunk_tokens(self, text: str, max_chunk_size=5, overlap=2) -> List[Tuple[int, int, str]]:
        """Split text into overlapping token chunks."""
        tokens = text.split()
        chunks = []
        for i in range(0, len(tokens), max_chunk_size - overlap):
            chunk_tokens = tokens[i:i + max_chunk_size]
            chunk_text = " ".join(chunk_tokens)
            start = text.find(chunk_tokens[0])
            end = text.find(chunk_tokens[-1], start) + len(chunk_tokens[-1])
            chunks.append((start, end, chunk_text))
        return chunks

    def detect_entities(self, text: str) -> List[Dict]:
        entities = []

        # 1. YAML rules (priority-ordered)
        for rule in self.rules:
            detection = rule["detection"]
            if detection["type"] == "regex":
                pattern = re.compile(detection["pattern"])
                for match in pattern.finditer(text):
                    val = match.group()
                    if val not in self.whitelist:
                        entities.append({
                            "entity": rule["column"],
                            "value": val,
                            "sensitive": True,
                            "confidence": 0.99,
                        })

            elif detection["type"] == "keyword":
                for kw in detection["keywords"]:
                    if kw.lower() in text.lower() and kw not in self.whitelist:
                        entities.append({
                            "entity": rule["column"],
                            "value": kw,
                            "sensitive": True,
                            "confidence": 0.98,
                        })

        # 2. spaCy NER (fallback, lower priority than YAML)
        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.text not in self.whitelist:
                entities.append({
                    "entity": ent.label_,
                    "value": ent.text,
                    "sensitive": True,
                    "confidence": 0.85,  # lower confidence than YAML
                })

        # 3. Chunked phone/email detection (high priority, regex-based)
        chunks = self._chunk_tokens(text)
        for _, _, chunk_text in chunks:
            for match in self.phone_regex.finditer(chunk_text):
                val = match.group()
                if val not in self.whitelist:
                    entities.append({"entity": "Phone Number", "value": val, "sensitive": True, "confidence": 1.0})
            for match in self.email_regex.finditer(chunk_text):
                val = match.group()
                if val not in self.whitelist:
                    entities.append({"entity": "Email", "value": val, "sensitive": True, "confidence": 1.0})

        # 4. Merge overlaps (keep highest priority/confidence)
        entities = self._merge_overlaps(entities)
        return entities

    def _merge_overlaps(self, entities: List[Dict]) -> List[Dict]:
        """Keep highest-confidence entity for overlapping text spans."""
        merged = []
        seen_values = set()
        for ent in sorted(entities, key=lambda x: (-x["confidence"], -len(x["value"]))):
            if ent["value"] not in seen_values:
                merged.append(ent)
                seen_values.add(ent["value"])
        return merged

    def scrub_text(self, text: str, entities: List[Dict] = None):
        if entities is None:
            entities = self.detect_entities(text)

        scrubbed_text = text
        enriched_entities = []

        entities.sort(key=lambda x: -len(x["value"]))  # replace longest first

        for ent in entities:
            if not ent.get("sensitive", True):
                continue

            value = ent["value"]
            if value.isdigit():
                value = self.fpe_encrypt(value)

            placeholder = self._make_placeholder(ent["entity"])
            scrubbed_text = scrubbed_text.replace(ent["value"], placeholder, 1)

            record = {
                "id": placeholder,
                "entity": ent["entity"],
                "value": ent["value"],
                "recommended_classification": self.rules_by_entity.get(ent["entity"], {}).get("recommended_classification", "UNKNOWN"),
                "confidence": ent.get("confidence", 1.0),
                "explanation": f"Detected via {'YAML rule' if ent['confidence'] >= 0.9 else 'spaCy'}"
            }
            self.mapping[placeholder] = record
            enriched_entities.append(record)

        return scrubbed_text, enriched_entities


