"""
Base strategy interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any

from ..core.entities import ScrubResult


class ScrubStrategy(ABC):
    """
    Abstract base class for scrubbing strategies.
    
    All detection strategies must implement this interface.
    """
    
    @abstractmethod
    def scrub(self, content: str, context: Dict[str, Any]) -> ScrubResult:
        """
        Detect and scrub sensitive entities.
        
        Args:
            content: Content to analyze
            context: Processing context with additional information
            
        Returns:
            ScrubResult containing detected entities
        """
        pass
    
    @abstractmethod
    def get_confidence(self) -> float:
        """
        Get the baseline confidence level of this strategy.
        
        Returns:
            Confidence score between 0.0 and 1.0
        """
        pass