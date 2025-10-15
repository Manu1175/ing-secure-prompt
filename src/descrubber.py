"""
DeScrubber - Secure restoration of scrubbed data
With access control and audit trail
"""

from typing import List, Dict, Tuple, Optional
from enum import Enum
from src.audit import AuditLogger
from src.vault import global_vault


class AccessLevel(Enum):
    """User access levels for de-scrubbing"""
    NONE = 0
    READ_ONLY = 1
    PARTIAL = 2
    FULL = 3
    ADMIN = 4


class AccessControlPolicy:
    """Define who can access what"""

    def __init__(self):
        # Role-based access control
        self.role_permissions = {
            "data_analyst": AccessLevel.READ_ONLY,
            "compliance_officer": AccessLevel.PARTIAL,
            "security_admin": AccessLevel.FULL,
            "system_admin": AccessLevel.ADMIN
        }

        # Entity-level restrictions
        self.entity_restrictions = {
            "SSN": [AccessLevel.ADMIN],
            "Credit Card": [AccessLevel.ADMIN],
            "Password": [AccessLevel.ADMIN],
            "Email": [AccessLevel.PARTIAL, AccessLevel.FULL, AccessLevel.ADMIN],
            "Phone Number": [AccessLevel.PARTIAL, AccessLevel.FULL, AccessLevel.ADMIN],
        }

    def can_access(self, user_role: str, entity_classification: str) -> bool:
        """Check if user role can access entity type"""
        user_level = self.role_permissions.get(user_role, AccessLevel.NONE)
        required_levels = self.entity_restrictions.get(
            entity_classification,
            [AccessLevel.PARTIAL, AccessLevel.FULL, AccessLevel.ADMIN]
        )
        return user_level in required_levels

    def add_role(self, role: str, level: AccessLevel):
        self.role_permissions[role] = level

    def restrict_entity(self, entity_type: str, levels: List[AccessLevel]):
        self.entity_restrictions[entity_type] = levels


class SecureVault:
    """Secure storage for placeholder-to-value mapping"""

    def __init__(self, storage_backend: str = "memory"):
        self.storage_backend = storage_backend
        self.vault = {}
        
    def load_from_mapping(self, mapping: Dict[str, Dict]):
        """Load scrubber mappings directly into the secure vault"""
        for placeholder, record in mapping.items():
            self.vault[placeholder] = {
                "value": record.get("value"),
                "classification": record.get("recommended_classification", "UNKNOWN"),
                "origin": record.get("explanation", "unknown"),
                "entity_type": record.get("entity", "UNKNOWN"),
                "confidence": record.get("confidence", 1.0),
                "source": "scrubber"
            }

    def store(self, placeholder_id: str, entity_data: Dict):
        self.vault[placeholder_id] = {
            "value": entity_data["value"],
            "classification": entity_data.get("classification", "UNKNOWN"),
            "origin": entity_data.get("explanation", "unknown"),
            "entity_type": entity_data.get("entity", "UNKNOWN"),
            "confidence": entity_data.get("confidence", 1.0),
            "source": entity_data.get("source", "unknown")
        }

    def retrieve(self, placeholder_id: str) -> Optional[Dict]:
        return self.vault.get(placeholder_id)

    def bulk_store(self, entities: List[Dict]):
        for entity in entities:
            placeholder_id = entity.get("id")
            if placeholder_id:
                self.store(placeholder_id, entity)

    def exists(self, placeholder_id: str) -> bool:
        return placeholder_id in self.vault

    def clear(self):
        self.vault.clear()

    def get_all_placeholders(self) -> List[str]:
        return list(self.vault.keys())


class DeScrubber:
    """Secure de-scrubbing with access control and audit"""

    def __init__(self, audit_logger: Optional[AuditLogger] = None,
                 access_policy: Optional[AccessControlPolicy] = None):
        self.vault = SecureVault()
        self.mapping = {}  # <-- initialize mapping here
        self.audit_logger = audit_logger or AuditLogger()
        self.access_policy = access_policy or AccessControlPolicy()
        self.vault = global_vault

    def store_placeholders(self, entities: List[Dict]):
        """Store entity placeholders in the vault"""
        self.vault.bulk_store(entities)
        print(f"Stored {len(entities)} placeholders in vault")

    def check_access(self, user_role: str, placeholder_ids: List[str]) -> Dict:
        """Check access permissions for requested placeholders"""
        allowed = []
        denied = []

        for pid in placeholder_ids:
            # entity_data = self.vault.retrieve(pid)

            pid_normalized = pid
            # wrap with double braces only if missing
            if not (pid.startswith("{{") and pid.endswith("}}")):
                pid_normalized = f"{{{{{pid.strip('{}')}}}}}"

            entity_data = self.vault.retrieve(pid_normalized)
            if not entity_data:
                entity_data = self.audit_logger.lookup_placeholder(pid_normalized)
                
            # Try audit log fallback if not found in vault
            if not entity_data:
                entity_data = self.audit_logger.lookup_placeholder(pid_normalized)
                if entity_data:
                    print(f"Recovered {pid_normalized} from audit log.")
                    # Re-store in vault for next time
                    self.vault.store(pid_normalized, entity_data)
                else:
                    denied.append({
                        "placeholder_id": pid_normalized,
                        "reason": "Placeholder not found in vault or audit log"
                    })
                    continue

            # Extract actual value here
            actual_value = entity_data.get("value")  # <-- new fix
            classification = entity_data.get("classification", "UNKNOWN")
            if self.access_policy.can_access(user_role, classification):
                allowed.append(pid_normalized)
            else:
                denied.append({
                    "placeholder_id": pid_normalized,
                    "classification": classification,
                    "reason": f"Insufficient permissions for {classification}"
                })
                self.audit_logger.log_access_decision(
                    user_id=user_role,
                    resource_id=pid,
                    granted=False,
                    reason=f"Insufficient permissions for {classification}"
                )

        return {"allowed": allowed, "denied": denied}

    def descrub(self, scrubbed_text: str,
                requested_placeholders: List[str],
                user_id: str,
                user_role: str,
                justification: str) -> Tuple[str, List[Dict], str, List[Dict]]:
        """Replace placeholders with original values"""
        access_check = self.check_access(user_role, requested_placeholders)
        allowed = access_check["allowed"]
        denied = access_check["denied"]

        restored_text = scrubbed_text
        restored_entities = []

        for pid in allowed:
            entity_data = self.vault.retrieve(pid)
            if entity_data:
                # Fix: extract the actual value
                original_value = entity_data.get("value", pid)  # fallback to pid if missing
                # original_value = entity_data["value"]
                restored_text = restored_text.replace(pid, original_value)
                restored_entities.append({
                    "id": pid,
                    "value": original_value,
                    "classification": entity_data["classification"],
                    "origin": entity_data["origin"]
                })
                self.audit_logger.log_access_decision(
                    user_id=user_id,
                    resource_id=pid,
                    granted=True,
                    reason=f"Access granted: {justification}"
                )

        audit_id = self.audit_logger.log_descrub(
                user_id=user_id,
                restored_text=restored_text,
                restored_entities=restored_entities,
                justification=justification
            )

        print(f"✅ De-scrubbing logged: {audit_id}")
        print(f"   Restored: {len(restored_entities)} entities")
        print(f"   Denied: {len(denied)} entities")

        return restored_text, restored_entities, audit_id, denied

    def partial_descrub(self, scrubbed_text: str,
                        requested_placeholders: List[str],
                        user_id: str,
                        user_role: str,
                        justification: str,
                        mask_method: str = "partial") -> Tuple[str, List[Dict], str]:
        """Partial de-scrubbing: masked version"""
        access_check = self.check_access(user_role, requested_placeholders)
        allowed = access_check["allowed"]

        restored_text = scrubbed_text
        restored_entities = []

        for pid in allowed:
            entity_data = self.vault.retrieve(pid)
            if entity_data:
                original_value = entity_data["value"]

                # Masking logic
                if mask_method == "partial":
                    if "@" in original_value:
                        parts = original_value.split("@")
                        masked = f"{parts[0][:2]}***@{parts[1]}"
                    elif len(original_value) > 4:
                        masked = f"{original_value[:2]}***{original_value[-2:]}"
                    else:
                        masked = "***"
                elif mask_method == "redacted":
                    masked = "[REDACTED]"
                else:
                    masked = f"[HASH:{hash(original_value) % 10000:04d}]"

                restored_text = restored_text.replace(pid, masked)
                restored_entities.append({
                    "id": pid,
                    "masked_value": masked,
                    "classification": entity_data["classification"]
                })

        audit_id = self.audit_logger.log_descrub(
            user_id=user_id,
            restored_text=restored_text,
            restored_entities=restored_entities,
            justification=f"PARTIAL: {justification}"
        )

        return restored_text, restored_entities, audit_id
