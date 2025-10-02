import hashlib
import json
import time
from typing import List, Dict, Optional
import numpy as np

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
    # Scrubbing / action logging
    # -------------------
    def log_action(
        self,
        user_id: str,
        original: str,
        scrubbed: str,
        entities: List[Dict],
        justification: Optional[str] = None,
        action: str = "scrub",
        device: str = "unknown_device",
        browser: str = "unknown_browser",
        location: str = "unknown_location",
    ) -> str:
        """
        Log a scrubbing or descrubbing action.
        Captures entities, placeholders, classification, and confidence.
        """
        # Detect intent from prompt (optional)
        lowered = original.lower()
        intent = None
        if "search" in lowered and "customer" in lowered:
            intent = "search_customer"
        elif "update" in lowered and "customer" in lowered:
            intent = "update_customer"
        elif "delete" in lowered and "customer" in lowered:
            intent = "delete_customer"
        elif "export" in lowered or "share" in lowered:
            intent = "share_data"

        # Compute overall confidence
        confidence = max((e.get("confidence", 0) for e in entities), default=0)

        record = {
            "event": "action",
            "action": action,  # "scrub" or "descrub"
            "timestamp": time.time(),
            "corporate_key": self.corporate_key,
            "user_id": user_id,
            "device": device,
            "browser": browser,
            "location": location,
            "original": original,
            "scrubbed": scrubbed,
            "entities": entities,  # includes placeholders and classification
            "justification": justification,
            "intent": intent,
            "confidence_level": confidence,
            "closure": "no_result" if scrubbed.strip() == "" else "success"
        }

        return self._append_log(record)
