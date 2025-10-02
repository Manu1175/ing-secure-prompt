"""
Regex-based detection strategy (Phase 1).
"""
import re
from typing import Dict, Any, List
from datetime import datetime

from ..core.entities import (
    DetectedEntity, EntityType, ConfidentialityLevel, ScrubResult
)
from .base import ScrubStrategy


class RegexStrategy(ScrubStrategy):
    """
    Phase 1 detection using regex patterns.
    
    Detects:
    - IBAN
    - Credit cards
    - Email addresses
    - Phone numbers (Belgian format)
    - Account numbers
    """
    
    # Pattern definitions
    PATTERNS = {
        EntityType.IBAN: {
            'pattern': r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b',
            'confidence': 0.95,
            'level': ConfidentialityLevel.C4,
            'explanation': 'Detected as IBAN by regex pattern'
        },
        EntityType.CREDIT_CARD: {
            'pattern': r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
            'confidence': 0.90,
            'level': ConfidentialityLevel.C4,
            'explanation': 'Detected as credit card by regex pattern'
        },
        EntityType.EMAIL: {
            'pattern': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'confidence': 0.85,
            'level': ConfidentialityLevel.C2,
            'explanation': 'Detected as email by regex pattern'
        },
        EntityType.PHONE: {
            'pattern': r'(?:\+32|0)[1-9]\d{8}',
            'confidence': 0.88,
            'level': ConfidentialityLevel.C3,
            'explanation': 'Detected as Belgian phone number'
        },
        EntityType.ACCOUNT_NUMBER: {
            'pattern': r'\b\d{3}-\d{7}-\d{2}\b',
            'confidence': 0.92,
            'level': ConfidentialityLevel.C4,
            'explanation': 'Detected as account number'
        }
    }
    
    def __init__(self, sensitivity: ConfidentialityLevel = ConfidentialityLevel.C2):
        """
        Initialize regex strategy.
        
        Args:
            sensitivity: Minimum confidentiality level to detect
        """
        self.sensitivity = sensitivity
        self._compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[EntityType, re.Pattern]:
        """Compile regex patterns for efficiency."""
        return {
            entity_type: re.compile(info['pattern'])
            for entity_type, info in self.PATTERNS.items()
        }
    
    def scrub(self, content: str, context: Dict[str, Any]) -> ScrubResult:
        """
        Detect entities using regex patterns.
        
        Args:
            content: Content to analyze
            context: Processing context
            
        Returns:
            ScrubResult with detected entities
        """
        entities: List[DetectedEntity] = []
        
        for entity_type, pattern in self._compiled_patterns.items():
            info = self.PATTERNS[entity_type]
            
            # Skip if below sensitivity level
            if info['level'] < self.sensitivity:
                continue
            
            # Find all matches
            for match in pattern.finditer(content):
                entity = DetectedEntity(
                    entity_type=entity_type,
                    original_value=match.group(),
                    start_pos=match.start(),
                    end_pos=match.end(),
                    confidence=info['confidence'],
                    confidentiality_level=info['level'],
                    explanation=info['explanation']
                )
                
                # Additional validation
                if self._validate_entity(entity):
                    entities.append(entity)
        
        # Calculate overall confidence
        confidence = self._calculate_confidence(entities)
        
        return ScrubResult(
            scrubbed_content=content,
            entities=entities,
            timestamp=datetime.now(),
            session_id=context.get('session_id', ''),
            confidence_score=confidence,
            metadata={'strategy': 'regex', 'pattern_count': len(self.PATTERNS)}
        )
    
    def _validate_entity(self, entity: DetectedEntity) -> bool:
        """
        Additional validation for detected entities.
        
        Args:
            entity: Entity to validate
            
        Returns:
            True if entity is valid
        """
        if entity.entity_type == EntityType.IBAN:
            return self._validate_iban(entity.original_value)
        elif entity.entity_type == EntityType.CREDIT_CARD:
            return self._validate_credit_card(entity.original_value)
        
        return True
    
    def _validate_iban(self, iban: str) -> bool:
        """
        Validate IBAN using mod-97 checksum.
        
        Args:
            iban: IBAN string to validate
            
        Returns:
            True if valid IBAN
        """
        # Remove spaces
        iban = iban.replace(' ', '').replace('-', '')
        
        # Basic length check
        if len(iban) < 15 or len(iban) > 34:
            return False
        
        # Move first 4 chars to end
        rearranged = iban[4:] + iban[:4]
        
        # Replace letters with numbers (A=10, B=11, etc.)
        numeric = ''
        for char in rearranged:
            if char.isdigit():
                numeric += char
            else:
                numeric += str(ord(char) - ord('A') + 10)
        
        # Check mod 97
        return int(numeric) % 97 == 1
    
    def _validate_credit_card(self, number: str) -> bool:
        """
        Validate credit card using Luhn algorithm.
        
        Args:
            number: Credit card number
            
        Returns:
            True if valid
        """
        # Remove spaces and dashes
        number = number.replace(' ', '').replace('-', '')
        
        if not number.isdigit():
            return False
        
        # Luhn algorithm
        def luhn_checksum(card_number):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_number)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d * 2))
            return checksum % 10
        
        return luhn_checksum(number) == 0
    
    def _calculate_confidence(self, entities: List[DetectedEntity]) -> float:
        """Calculate overall confidence score."""
        if not entities:
            return 1.0
        return sum(e.confidence for e in entities) / len(entities)
    
    def get_confidence(self) -> float:
        """Return strategy's baseline confidence."""
        return 0.85