import re
from typing import List, Dict
import pandas as pd
import glob
import yaml
from collections import Counter, defaultdict
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
import os

class Classifier:
    def __init__(self, ner_model_path: str = None, rules_yaml: str = "./datasets/rules_updated.yaml"):
        self.regex_patterns = {}
        self.keyword_map = {}
        self.load_rules_from_yaml(rules_yaml)
        if not self.keyword_map:
            self.keyword_map = {}  # avoid None

        if ner_model_path:
            self.ner_tokenizer = AutoTokenizer.from_pretrained(ner_model_path)
            self.ner_model = AutoModelForTokenClassification.from_pretrained(ner_model_path)
            self.ner_pipeline = pipeline(
                "ner",
                model=self.ner_model,
                tokenizer=self.ner_tokenizer,
                aggregation_strategy="simple"
            )
        else:
            self.ner_pipeline = None

    def load_rules_from_yaml(self, yaml_path: str):
        with open(yaml_path, "r") as f:
            rules = yaml.safe_load(f)["rules"]

        for rule in rules:
            det = rule.get("detection", {})
            classification = rule.get("classification", "C1")
            label = rule.get("column") or rule.get("placeholder") or "UNKNOWN"

            if det.get("type") == "regex" and "pattern" in det:
                self.regex_patterns[label] = (det["pattern"], classification)
            elif det.get("type") == "keyword" and "keywords" in det:
                self.keyword_map[label] = (det["keywords"], classification)

    def classify(self, text: str) -> List[Dict]:
        raw_entities = []

        # 1. Regex detection
        for label, (pattern, classification) in self.regex_patterns.items():
            for match in re.finditer(pattern, text):
                raw_entities.append({
                    "entity": label,
                    "value": match.group(),
                    "classification": classification,
                    "confidence": 0.95,
                    "source": "regex"
                })

        # 2. Keyword detection
        lower_text = text.lower()
        for label, (keywords, classification) in self.keyword_map.items():
            for kw in keywords:
                if kw.lower() in lower_text:
                    raw_entities.append({
                        "entity": label,
                        "value": kw,
                        "classification": classification,
                        "confidence": 0.8,
                        "source": "keyword"
                    })

        # 3. NER detection
        if self.ner_pipeline:
            ner_results = self.ner_pipeline(text)
            for r in ner_results:
                raw_entities.append({
                    "entity": r["entity_group"],
                    "value": r["word"],
                    "start": r["start"],
                    "end": r["end"],
                    "classification": self.map_ner_to_class(r["entity_group"]),
                    "confidence": r["score"],
                    "source": "ner"
                })

        # --- Merge duplicates / same value detections ---
        merged = {}
        for e in raw_entities:
            key = e["value"].lower()
            if key not in merged:
                merged[key] = e.copy()
            else:
                # merge confidence: 1 - (product of (1-confidence))
                prev_conf = merged[key]["confidence"]
                new_conf = e["confidence"]
                merged[key]["confidence"] = 1 - (1 - prev_conf) * (1 - new_conf)
                # merge sources
                merged[key]["source"] += f",{e['source']}"

        return list(merged.values())

    def map_ner_to_class(self, entity_group: str) -> str:
        mapping = {"PER": "C2", "ORG": "C3", "LOC": "C2", "MISC": "C3"}
        return mapping.get(entity_group, "C1")
