# src/api/scrubber.py
"""
Enhanced Scrubber - Strategy Pattern + YAML Configuration
Integration with AuditLogger for traceability
"""
from __future__ import annotations

import re
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

import yaml

# spaCy est optionnel: si le modèle n'est pas dispo, on continue sans NER
try:
    import spacy  # type: ignore
except Exception:
    spacy = None  # fallback

# Flexible import pour différents layouts de projet
try:
    from audit import AuditLogger  # type: ignore
except Exception:
    try:
        from src.api.audit import AuditLogger  # type: ignore
    except Exception:
        AuditLogger = None  # type: ignore

# Optionnel : FPE (Format-Preserving Encryption) via pyffx
try:
    import pyffx  # type: ignore
    HAS_FPE = True
except Exception:
    HAS_FPE = False
    print("⚠️  pyffx non installé. Chiffrement FPE désactivé.")


# ----------------------
# Strategies de détection
# ----------------------
class EntityDetectionStrategy:
    """Strategy Pattern: différentes méthodes de détection."""
    def detect(self, text: str, whitelist: set) -> List[Dict]:
        raise NotImplementedError


class YAMLRuleStrategy(EntityDetectionStrategy):
    """Détection basée sur les règles YAML (priorisées)."""
    def __init__(self, rules: List[Dict]):
        self.rules = sorted(rules, key=lambda r: r.get("priority", 5))

    def detect(self, text: str, whitelist: set) -> List[Dict]:
        entities: List[Dict] = []
        low_text = text.lower()

        for rule in self.rules:
            detection = rule.get("detection", {})
            entity_name = rule.get("column", "UNKNOWN")
            dtype = detection.get("type")

            if dtype == "regex":
                pattern = detection.get("pattern", "")
                if not pattern:
                    continue
                try:
                    rx = re.compile(pattern)
                except re.error:
                    # Règle invalide → on ignore sans casser
                    continue

                for m in rx.finditer(text):
                    val = m.group()
                    if val not in whitelist:
                        entities.append({
                            "entity": entity_name,
                            "value": val,
                            "sensitive": True,
                            "confidence": float(rule.get("confidence", 0.99)),
                            "source": "yaml_regex",
                        })

            elif dtype == "keyword":
                for kw in detection.get("keywords", []):
                    if not kw:
                        continue
                    # match insensible à la casse
                    if kw.lower() in low_text and kw not in whitelist:
                        entities.append({
                            "entity": entity_name,
                            "value": kw,
                            "sensitive": True,
                            "confidence": float(rule.get("confidence", 0.98)),
                            "source": "yaml_keyword",
                        })

        return entities


class SpacyNERStrategy(EntityDetectionStrategy):
    """Détection NER spaCy (fallback)."""
    def __init__(self, model: str = "en_core_web_sm"):
        self.nlp = None
        if spacy is not None:
            try:
                self.nlp = spacy.load(model)  # type: ignore
            except Exception:
                print("⚠️  Modèle spaCy introuvable. NER désactivé.")

    def detect(self, text: str, whitelist: set) -> List[Dict]:
        if not self.nlp:
            return []
        out: List[Dict] = []
        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.text not in whitelist:
                out.append({
                    "entity": ent.label_,
                    "value": ent.text,
                    "sensitive": True,
                    "confidence": 0.85,
                    "source": "spacy_ner",
                })
        return out


class RegexPatternsStrategy(EntityDetectionStrategy):
    """Regex haute priorité : téléphone, email."""
    def __init__(self):
        self.phone_regex = re.compile(
            r"(?:\+?\d{1,3})?[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}"
        )
        self.email_regex = re.compile(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        )

    def detect(self, text: str, whitelist: set) -> List[Dict]:
        entities: List[Dict] = []

        for m in self.phone_regex.finditer(text):
            val = m.group()
            if val not in whitelist:
                entities.append({
                    "entity": "Phone Number",
                    "value": val,
                    "sensitive": True,
                    "confidence": 1.0,
                    "source": "regex_phone",
                })

        for m in self.email_regex.finditer(text):
            val = m.group()
            if val not in whitelist:
                entities.append({
                    "entity": "Email",
                    "value": val,
                    "sensitive": True,
                    "confidence": 1.0,
                    "source": "regex_email",
                })

        return entities


# --------------
# Classe Scrubber
# --------------
class Scrubber:
    """Scrubber principal (Strategies + YAML + Audit)."""

    def __init__(
        self,
        rules_yaml: str,
        whitelist_yaml: Optional[str] = None,
        fpe_key: str = "secure-key-32-bytes-minimum!",
        audit_logger: Optional[AuditLogger] = None,
    ):
        # Charger les règles
        with open(rules_yaml, "r", encoding="utf-8") as f:
            rules_data = yaml.safe_load(f) or {}

        self.rules: List[Dict] = rules_data.get("rules", [])
        for r in self.rules:
            r.setdefault("priority", 5)

        # Charger la whitelist
        self.whitelist: set = set()
        if whitelist_yaml:
            try:
                with open(whitelist_yaml, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or []
                for entry in data:
                    if isinstance(entry, dict) and entry.get("type") == "domain_term":
                        txt = (entry.get("text") or "").strip()
                        if txt:
                            self.whitelist.add(txt)
                    elif isinstance(entry, str):
                        self.whitelist.add(entry.strip())
            except FileNotFoundError:
                print(f"⚠️  Fichier whitelist introuvable: {whitelist_yaml}")

        # Enregistrer les stratégies
        self.strategies: List[EntityDetectionStrategy] = [
            RegexPatternsStrategy(),
            YAMLRuleStrategy(self.rules),
            SpacyNERStrategy(),  # activé seulement si spaCy + modèle présents
        ]

        # FPE
        self.fpe_key = fpe_key
        self.fpe_available = HAS_FPE

        # Placeholders
        self.mapping: Dict[str, Dict] = {}
        self.placeholder_counters = defaultdict(int)
        self.rules_by_entity = {r.get("column", "UNKNOWN"): r for r in self.rules}

        # Audit
        self.audit_logger = audit_logger

    # ---------- Utils ----------
    def fpe_encrypt(self, value: str) -> str:
        """Chiffrement FPE (si numérique)"""
        if not self.fpe_available:
            return value
        if value.isdigit() and 6 <= len(value) <= 12:
            try:
                return pyffx.String(
                    self.fpe_key.encode(),
                    alphabet="0123456789",
                    length=len(value)
                ).encrypt(value)
            except Exception:
                return value
        return value

    def _make_placeholder(self, entity_name: str) -> str:
        """Crée un placeholder unique pour une entité."""
        rule = self.rules_by_entity.get(entity_name)
        if rule and "placeholder" in rule and rule["placeholder"]:
            # Si une valeur fixe est fournie, on la réutilise
            return rule["placeholder"]

        self.placeholder_counters[entity_name] += 1
        return f"{{{{{entity_name}_{self.placeholder_counters[entity_name]}}}}}"

    # ---------- Détection ----------
    def detect_entities(self, text: str) -> List[Dict]:
        all_entities: List[Dict] = []
        for strat in self.strategies:
            try:
                ents = strat.detect(text, self.whitelist)
                all_entities.extend(ents)
            except Exception as e:
                print(f"⚠️  Strategy {strat.__class__.__name__} erreur: {e}")

        return self._merge_overlaps(all_entities)

    def _merge_overlaps(self, entities: List[Dict]) -> List[Dict]:
        """Déduplique par valeur en gardant la meilleure confiance + la plus longue valeur."""
        merged: List[Dict] = []
        seen_values = set()
        sorted_entities = sorted(
            entities, key=lambda x: (-float(x.get("confidence", 0)), -len(x.get("value", ""))))
        for ent in sorted_entities:
            val = ent.get("value", "")
            if val and val not in seen_values:
                merged.append(ent)
                seen_values.add(val)
        return merged

    # ---------- Scrubbing ----------
    def scrub_text(
        self,
        text: str,
        user_id: str = "system",
        entities: Optional[List[Dict]] = None
    ) -> Tuple[str, List[Dict]]:
        """Remplace les valeurs sensibles par placeholders, retourne (texte, entités_enrichies)."""
        if entities is None:
            entities = self.detect_entities(text)

        scrubbed_text = text
        enriched: List[Dict] = []

        # Remplacer d'abord les plus longues occurrences
        entities.sort(key=lambda x: -len(x.get("value", "")))

        for ent in entities:
            if not ent.get("sensitive", True):
                continue

            val = ent.get("value", "")
            if not val:
                continue

            replaced_val = self.fpe_encrypt(val) if val.isdigit() else val
            placeholder = self._make_placeholder(ent.get("entity", "UNKNOWN"))

            # Remplacement 1 seule fois par occurrence détectée
            scrubbed_text = scrubbed_text.replace(val, placeholder, 1)

            record = {
                "id": placeholder,
                "entity": ent.get("entity", "UNKNOWN"),
                "value": val,
                "classification": self.rules_by_entity.get(
                    ent.get("entity", "UNKNOWN"), {}
                ).get("recommended_classification", "UNKNOWN"),
                "confidence": float(ent.get("confidence", 1.0)),
                "source": ent.get("source", "unknown"),
                "explanation": f"Detected via {ent.get('source', 'unknown')}",
            }
            self.mapping[placeholder] = record
            enriched.append(record)

        # Audit (optionnel)
        if self.audit_logger:
            try:
                audit_id = self.audit_logger.log_scrub(
                    user_id=user_id,
                    original_text=text,
                    scrubbed_text=scrubbed_text,
                    entities=enriched,
                )
                print(f"✅ Scrubbing journalisé: {audit_id}")
            except Exception as e:
                print(f"⚠️  Audit logging échec: {e}")

        return scrubbed_text, enriched

    def get_mapping(self) -> Dict:
        return self.mapping.copy()
