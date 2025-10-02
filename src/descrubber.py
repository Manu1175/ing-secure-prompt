from audit import AuditLogger

class DeScrubber:
    def __init__(self, audit_logger: AuditLogger):
        # Placeholder → original value mapping (in-memory for MVP)
        self.vault = {}
        self.audit_logger = audit_logger

    def store_placeholders(self, entities):
        """
        Store entity placeholders in the vault for later de-scrubbing
        """
        for e in entities:
            placeholder_id = e.get("id")
            if placeholder_id:
                self.vault[placeholder_id] = {
                    "value": e["value"],
                    "classification": e["classification"],
                    "origin": e.get("explanation", "unknown")
                }

    def descrub(self, scrubbed_text: str, requested_placeholders: list, user_id: str, justification: str):
        """
        Replace placeholders in scrubbed_text with original values
        requested_placeholders: list of placeholder IDs to restore
        """
        restored_text = scrubbed_text
        restored_entities = []

        for pid in requested_placeholders:
            if pid in self.vault:
                original_value = self.vault[pid]["value"]
                restored_text = restored_text.replace(pid, original_value)
                restored_entities.append({
                    "id": pid,
                    "value": original_value,
                    "classification": self.vault[pid]["classification"],
                    "origin": self.vault[pid]["origin"]
                })

        # Log de-scrubbing action
        audit_id = self.audit_logger.log_descrub(
            user_id=user_id,
            restored_text=restored_text,
            restored_entities=restored_entities,
            justification=justification
        )

        return restored_text, restored_entities, audit_id
