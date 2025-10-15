import hashlib
import json
import time
from typing import List, Dict, Optional
import numpy as np
import uuid


class AuditLogger:
    def __init__(self, logfile: str, corporate_key: str = "ING_CORP_KEY_001"):
        self.logfile = logfile
        self.corporate_key = corporate_key
        self.last_hash = "0"  # blockchain root

    # -------------------
    # Serialization helper
    # -------------------
    def _convert_to_serializable(self, obj):
        """Recursively convert non-JSON-serializable objects to standard Python types."""
        if isinstance(obj, dict):
            return {k: self._convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_serializable(x) for x in obj]
        elif isinstance(obj, (np.float32, np.float64)):
            return float(obj)
        elif isinstance(obj, (np.int32, np.int64)):
            return int(obj)
        else:
            return obj

    # -------------------
    # Hashing / logging
    # -------------------
    def _hash_record(self, record: dict) -> str:
        """Create SHA256 hash of record + previous hash (blockchain style)."""
        record_serializable = self._convert_to_serializable(record)
        record_str = json.dumps(record_serializable, sort_keys=True)
        return hashlib.sha256((record_str + self.last_hash).encode()).hexdigest()

    def _append_log(self, record: dict) -> str:
        """Append record to file with hash chaining."""
        record_serializable = self._convert_to_serializable(record)
        record_serializable["hash"] = self._hash_record(record_serializable)
        self.last_hash = record_serializable["hash"]

        with open(self.logfile, "a") as f:
            f.write(json.dumps(record_serializable) + "\n")

        return record_serializable["hash"]

    # -------------------
    # Session logging
    # -------------------
    def log_session(self, user_id: str, action: str, device: str, browser: str, location: str):
        record = {
            "event": "session",
            "action": action,  # logon, logoff, open_session, close_session
            "timestamp": time.time(),
            "corporate_key": self.corporate_key,
            "user_id": user_id,
            "device": device,
            "browser": browser,
            "location": location,
        }
        return self._append_log(record)

    # -------------------
    # Scrubbing / generic action logging
    # -------------------
    def log_action(
        self,
        user_id: str,
        original: str,
        scrubbed: str,
        entities: List[Dict],
        justification: Optional[str] = None,
        action: str = "scrub",  # "scrub", "descrub", "llm_response"
        device: str = "unknown_device",
        session_id: Optional[str] = None,
        browser: str = "unknown_browser",
        location: str = "unknown_location",
        llm_model: Optional[str] = None,
        llm_tokens: Optional[int] = None,
    ) -> str:
        """
        Log a scrubbing, descrubbing, or LLM response action.
        Captures entities, placeholders, classification, and confidence.
        All actions within one user prompt share the same session_id.
        """
        if not session_id:
            session_id = str(uuid.uuid4())

        lowered = original.lower() if original else ""
        intent = None
        if "search" in lowered and "customer" in lowered:
            intent = "search_customer"
        elif "update" in lowered and "customer" in lowered:
            intent = "update_customer"
        elif "delete" in lowered and "customer" in lowered:
            intent = "delete_customer"
        elif "export" in lowered or "share" in lowered:
            intent = "share_data"

        confidence = max(
            (e.get("confidence", 0) if isinstance(e, dict) else getattr(e, "confidence", 0))
            for e in entities
        ) if entities else 0

        record = {
            "event": "action",
            "session_id": session_id,
            "action": action,
            "timestamp": time.time(),
            "corporate_key": self.corporate_key,
            "user_id": user_id,
            "device": device,
            "browser": browser,
            "location": location,
            "original": original,
            "scrubbed": scrubbed,
            "entities": entities,
            "justification": justification,
            "intent": intent,
            "confidence_level": confidence,
            "closure": "no_result" if not scrubbed.strip() else "success",
        }

        if action == "llm_response":
            record["llm_model"] = llm_model or "unknown_model"
            record["llm_tokens"] = llm_tokens or 0

        return self._append_log(record)

    # -------------------
    # Fallback lookup (for descrubbing)
    # -------------------
    def lookup_placeholder(self, placeholder_id: str) -> Optional[Dict]:
        """
        Look up a placeholder in the audit log and return its last known mapping.
        Searches the log from latest to oldest to find the most recent occurrence.
        """
        try:
            with open(self.logfile, "r") as f:
                lines = f.readlines()

            # Reverse iterate for most recent match
            for line in reversed(lines):
                try:
                    record = json.loads(line)
                    if record.get("event") in ["scrub", "action"]:
                        for ent in record.get("entities", []):
                            if ent.get("id") == placeholder_id:
                                return {
                                    "value": ent.get("value"),
                                    "classification": ent.get("classification", "UNKNOWN"),
                                    "origin": ent.get("origin", "audit_log"),
                                    "entity_type": ent.get("entity", "UNKNOWN"),
                                    "confidence": ent.get("confidence", 1.0),
                                    "source": "audit_log"
                                }
                except Exception:
                    continue  # skip bad lines silently

            return None  # not found

        except FileNotFoundError:
            return None

    # -------------------
    # Access control decision logging
    # -------------------
    def log_access_decision(self, user_id: str, resource_id: str, granted: bool, reason: str) -> str:
        """Logs access control decision for a specific placeholder/entity."""
        record = {
            "event": "access_decision",
            "timestamp": time.time(),
            "corporate_key": self.corporate_key,
            "user_id": user_id,
            "resource_id": resource_id,
            "granted": granted,
            "reason": reason,
        }
        return self._append_log(record)

    # -------------------
    # De-scrubbing audit event
    # -------------------
    def log_descrub(self, user_id: str, restored_text: str, restored_entities: list, justification: str) -> str:
        """Dedicated method for descrubbing audit trail (used by DeScrubber)."""
        audit_id = str(uuid.uuid4())
        record = {
            "event": "descrub",
            "audit_id": audit_id,
            "timestamp": time.time(),
            "corporate_key": self.corporate_key,
            "user_id": user_id,
            "justification": justification,
            "restored_entities": restored_entities,
            "restored_text_preview": restored_text[:300] if restored_text else "",
            "entity_count": len(restored_entities),
        }
        return self._append_log(record)
    


