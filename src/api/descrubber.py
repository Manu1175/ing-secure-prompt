"""
DeScrubber - Secure restoration of scrubbed data
With access control and audit trail
"""
from typing import List, Dict, Tuple, Optional
from audit import AuditLogger
from enum import Enum


class AccessLevel(Enum):
    """User access levels for de-scrubbing"""
    NONE = 0
    READ_ONLY = 1
    PARTIAL = 2
    FULL = 3
    ADMIN = 4


class AccessControlPolicy:
    """
    Policy pattern: define who can access what
    """
    
    def __init__(self):
        # Role-based access control
        self.role_permissions = {
            "data_analyst": AccessLevel.READ_ONLY,
            "compliance_officer": AccessLevel.PARTIAL,
            "security_admin": AccessLevel.FULL,
            "system_admin": AccessLevel.ADMIN
        }
        
        # Entity-level permissions
        self.entity_restrictions = {
            "SSN": [AccessLevel.ADMIN],
            "Credit Card": [AccessLevel.ADMIN],
            "Password": [AccessLevel.ADMIN],
            "Email": [AccessLevel.PARTIAL, AccessLevel.FULL, AccessLevel.ADMIN],
            "Phone Number": [AccessLevel.PARTIAL, AccessLevel.FULL, AccessLevel.ADMIN],
        }
    
    def can_access(self, user_role: str, entity_classification: str) -> bool:
        """
        Check if user role can access entity type
        """
        user_level = self.role_permissions.get(user_role, AccessLevel.NONE)
        
        required_levels = self.entity_restrictions.get(
            entity_classification, 
            [AccessLevel.PARTIAL, AccessLevel.FULL, AccessLevel.ADMIN]
        )
        
        return user_level in required_levels
    
    def add_role(self, role: str, level: AccessLevel):
        """Add custom role"""
        self.role_permissions[role] = level
    
    def restrict_entity(self, entity_type: str, levels: List[AccessLevel]):
        """Add entity-level restriction"""
        self.entity_restrictions[entity_type] = levels


class SecureVault:
    """
    Secure storage for placeholder-to-value mapping
    Chain of Responsibility pattern for storage backends
    """
    
    def __init__(self, storage_backend: str = "memory"):
        self.storage_backend = storage_backend
        self.vault = {}  # In-memory for MVP
        
        # Could extend to: Redis, HashiCorp Vault, Azure Key Vault
    
    def store(self, placeholder_id: str, entity_data: Dict):
        """Store entity data securely"""
        self.vault[placeholder_id] = {
            "value": entity_data["value"],
            "classification": entity_data.get("classification", "UNKNOWN"),
            "origin": entity_data.get("explanation", "unknown"),
            "entity_type": entity_data.get("entity", "UNKNOWN"),
            "confidence": entity_data.get("confidence", 1.0),
            "source": entity_data.get("source", "unknown")
        }
    
    def retrieve(self, placeholder_id: str) -> Optional[Dict]:
        """Retrieve entity data"""
        return self.vault.get(placeholder_id)
    
    def bulk_store(self, entities: List[Dict]):
        """Store multiple entities"""
        for entity in entities:
            placeholder_id = entity.get("id")
            if placeholder_id:
                self.store(placeholder_id, entity)
    
    def exists(self, placeholder_id: str) -> bool:
        """Check if placeholder exists"""
        return placeholder_id in self.vault
    
    def clear(self):
        """Clear vault (use with caution!)"""
        self.vault.clear()
    
    def get_all_placeholders(self) -> List[str]:
        """Get all stored placeholder IDs"""
        return list(self.vault.keys())


class DeScrubber:
    """
    Secure de-scrubbing with access control and audit
    """
    
    def __init__(self, audit_logger: Optional[AuditLogger] = None,
                 access_policy: Optional[AccessControlPolicy] = None):
        
        self.vault = SecureVault()
        self.audit_logger = audit_logger or AuditLogger()
        self.access_policy = access_policy or AccessControlPolicy()
    
    def store_placeholders(self, entities: List[Dict]):
        """
        Store entity placeholders in the vault for later de-scrubbing
        
        Args:
            entities: List of enriched entities from Scrubber
        """
        self.vault.bulk_store(entities)
        print(f" Stored {len(entities)} placeholders in vault")
    
    def check_access(self, user_role: str, placeholder_ids: List[str]) -> Dict:
        """
        Check access permissions for requested placeholders
        
        Returns:
            {
                "allowed": [list of allowed placeholder IDs],
                "denied": [list of denied placeholder IDs with reasons]
            }
        """
        allowed = []
        denied = []
        
        for pid in placeholder_ids:
            entity_data = self.vault.retrieve(pid)
            
            if not entity_data:
                denied.append({
                    "placeholder_id": pid,
                    "reason": "Placeholder not found in vault"
                })
                continue
            
            classification = entity_data.get("classification", "UNKNOWN")
            
            if self.access_policy.can_access(user_role, classification):
                allowed.append(pid)
            else:
                denied.append({
                    "placeholder_id": pid,
                    "classification": classification,
                    "reason": f"Insufficient permissions for {classification}"
                })
                
                # Log access denial
                self.audit_logger.log_access_decision(
                    user_id=user_role,
                    resource_id=pid,
                    granted=False,
                    reason=f"Insufficient permissions for {classification}"
                )
        
        return {
            "allowed": allowed,
            "denied": denied
        }
    
    def descrub(self, scrubbed_text: str, 
                requested_placeholders: List[str], 
                user_id: str, 
                user_role: str,
                justification: str) -> Tuple[str, List[Dict], str, List[Dict]]:
        """
        Replace placeholders in scrubbed_text with original values
        With access control and audit trail
        
        Args:
            scrubbed_text: Text with placeholders
            requested_placeholders: List of placeholder IDs to restore
            user_id: User requesting de-scrubbing
            user_role: User's role (for access control)
            justification: Business justification for de-scrubbing
        
        Returns:
            (restored_text, restored_entities, audit_id, access_denied_entities)
        """
        # Check access permissions
        access_check = self.check_access(user_role, requested_placeholders)
        allowed_placeholders = access_check["allowed"]
        denied_items = access_check["denied"]
        
        # Restore allowed placeholders
        restored_text = scrubbed_text
        restored_entities = []
        
        for pid in allowed_placeholders:
            entity_data = self.vault.retrieve(pid)
            if entity_data:
                original_value = entity_data["value"]
                restored_text = restored_text.replace(pid, original_value)
                
                restored_entities.append({
                    "id": pid,
                    "value": original_value,
                    "classification": entity_data["classification"],
                    "origin": entity_data["origin"]
                })
                
                # Log successful access
                self.audit_logger.log_access_decision(
                    user_id=user_id,
                    resource_id=pid,
                    granted=True,
                    reason=f"Access granted: {justification}"
                )
        
        # Log de-scrubbing operation
        audit_id = self.audit_logger.log_descrub(
            user_id=user_id,
            restored_text=restored_text,
            restored_entities=restored_entities,
            justification=justification
        )
        
        print(f"✅ De-scrubbing logged: {audit_id}")
        print(f"   Restored: {len(restored_entities)} entities")
        print(f"   Denied: {len(denied_items)} entities")
        
        return restored_text, restored_entities, audit_id, denied_items
    
    def partial_descrub(self, scrubbed_text: str, 
                       requested_placeholders: List[str],
                       user_id: str,
                       user_role: str,
                       justification: str,
                       mask_method: str = "partial") -> Tuple[str, List[Dict], str]:
        """
        Partial de-scrubbing: show masked version instead of full value
        
        mask_method:
            - "partial": Show first/last chars (e.g., jo***@email.com)
            - "redacted": Show [REDACTED]
            - "hashed": Show hash of value
        """
        access_check = self.check_access(user_role, requested_placeholders)
        allowed_placeholders = access_check["allowed"]
        
        restored_text = scrubbed_text
        restored_entities = []
        
        for pid in allowed_placeholders:
            entity_data = self.vault.retrieve(pid)
            if entity_data:
                original_value = entity_data["value"]
                
                # Apply masking
                if mask_method == "partial":
                    if "@" in original_value:  # Email
                        parts = original_value.split("@")
                        masked = f"{parts[0][:2]}***@{parts[1]}"
                    elif len(original_value) > 4:
                        masked = f"{original_value[:2]}***{original_value[-2:]}"
                    else:
                        masked = "***"
                elif mask_method == "redacted":
                    masked = "[REDACTED]"
                else:  # hashed
                    masked = f"[HASH:{hash(original_value) % 10000:04d}]"
                
                restored_text = restored_text.replace(pid, masked)
                
                restored_entities.append({
                    "id": pid,
                    "masked_value": masked,
                    "classification": entity_data["classification"]
                })
        
        # Log partial de-scrubbing
        audit_id = self.audit_logger.log_descrub(
            user_id=user_id,
            restored_text=restored_text,
            restored_entities=restored_entities,
            justification=f"PARTIAL: {justification}"
        )
        
        return restored_text, restored_entities, audit_id