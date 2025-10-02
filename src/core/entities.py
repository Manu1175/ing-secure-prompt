"""
Core entities for SecurePrompt system.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
import hashlib
import json


class ConfidentialityLevel(Enum):
    """Banking confidentiality levels."""
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"
    
    def __lt__(self, other: 'ConfidentialityLevel') -> bool:
        order = {'C2': 2, 'C3': 3, 'C4': 4}
        return order[self.value] < order[other.value]


class EntityType(Enum):
    """Types of detectable sensitive entities."""
    CUSTOMER_NAME = "customer_name"
    IBAN = "iban"
    CREDIT_CARD = "credit_card"
    ADDRESS = "address"
    PHONE = "phone"
    EMAIL = "email"
    ACCOUNT_NUMBER = "account_number"


@dataclass
class DetectedEntity:
    """
    Represents a detected sensitive entity.
    
    Attributes:
        entity_type: Type of the entity
        original_value: The actual sensitive value
        start_pos: Starting position in content
        end_pos: Ending position in content
        confidence: Detection confidence (0.0-1.0)
        confidentiality_level: Security classification
        replacement_id: Unique identifier for replacement
        explanation: Why this was detected
        metadata: Additional contextual information
    """
    entity_type: EntityType
    original_value: str
    start_pos: int
    end_pos: int
    confidence: float
    confidentiality_level: ConfidentialityLevel
    replacement_id: str = field(default="")
    explanation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Generate replacement_id if not provided."""
        if not self.replacement_id:
            content = f"{datetime.now().isoformat()}_{self.original_value}"
            self.replacement_id = hashlib.md5(content.encode()).hexdigest()[:8].upper()
        
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0 and 1")
    
    def get_replacement_token(self) -> str:
        """
        Generate contextual replacement token.
        
        Returns:
            Token like [IBAN_A3F2] or [CLIENT_B7E4]
        """
        prefix_map = {
            EntityType.CUSTOMER_NAME: "CLIENT",
            EntityType.IBAN: "IBAN",
            EntityType.CREDIT_CARD: "CARD",
            EntityType.ADDRESS: "ADDR",
            EntityType.PHONE: "PHONE",
            EntityType.EMAIL: "EMAIL",
            EntityType.ACCOUNT_NUMBER: "ACCT"
        }
        prefix = prefix_map.get(self.entity_type, "REDACTED")
        return f"[{prefix}_{self.replacement_id[:4]}]"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'entity_type': self.entity_type.value,
            'original_value': self.original_value,
            'start_pos': self.start_pos,
            'end_pos': self.end_pos,
            'confidence': self.confidence,
            'confidentiality_level': self.confidentiality_level.value,
            'replacement_id': self.replacement_id,
            'replacement_token': self.get_replacement_token(),
            'explanation': self.explanation,
            'metadata': self.metadata
        }


@dataclass
class ScrubResult:
    """
    Result of a scrubbing operation.
    
    Attributes:
        scrubbed_content: Content with entities replaced
        entities: List of detected entities
        timestamp: When scrubbing occurred
        session_id: Unique session identifier
        confidence_score: Overall confidence
        original_content: Original content (for audit)
        metadata: Additional operation metadata
    """
    scrubbed_content: str
    entities: List[DetectedEntity]
    timestamp: datetime
    session_id: str
    confidence_score: float
    original_content: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_entity_count(self) -> int:
        """Get total number of entities."""
        return len(self.entities)
    
    def get_entities_by_type(self, entity_type: EntityType) -> List[DetectedEntity]:
        """Filter entities by type."""
        return [e for e in self.entities if e.entity_type == entity_type]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'scrubbed_content': self.scrubbed_content,
            'entities': [e.to_dict() for e in self.entities],
            'timestamp': self.timestamp.isoformat(),
            'session_id': self.session_id,
            'confidence_score': self.confidence_score,
            'entity_count': self.get_entity_count(),
            'metadata': self.metadata
        }