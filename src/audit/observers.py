"""
Observer pattern for audit system.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any
import json

from ..core.entities import ScrubResult


@dataclass
class AuditEvent:
    """
    Immutable audit event.
    
    Attributes:
        event_type: Type of event (scrubbing, descrubbing, etc.)
        timestamp: When event occurred
        handler: Which component handled the event
        result: Scrubbing result
        context: Additional context
    """
    event_type: str
    handler: str
    result: ScrubResult
    context: Dict[str, Any]
    timestamp: datetime


class AuditObserver(ABC):
    """
    Abstract observer for audit events.
    """
    
    @abstractmethod
    def update(self, event: AuditEvent):
        """
        React to an audit event.
        
        Args:
            event: The audit event to process
        """
        pass


class EventStore(AuditObserver):
    """
    Append-only event store for audit trail.
    
    Implements Event Sourcing pattern.
    """
    
    def __init__(self, storage_path: str = "audit_events.jsonl"):
        """
        Initialize event store.
        
        Args:
            storage_path: Path to JSONL file for events
        """
        self.storage_path = storage_path
        self.events: list[AuditEvent] = []
    
    def update(self, event: AuditEvent):
        """
        Store event immutably.
        
        Args:
            event: Event to store
        """
        self.events.append(event)
        self._persist(event)
    
    def _persist(self, event: AuditEvent):
        """
        Persist event to append-only file.
        
        Args:
            event: Event to persist
        """
        event_dict = {
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type,
            'handler': event.handler,
            'session_id': event.result.session_id,
            'entity_count': len(event.result.entities),
            'confidence': event.result.confidence_score,
            'context': event.context
        }
        
        with open(self.storage_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event_dict) + '\n')
    
    def replay(self) -> list[AuditEvent]:
        """
        Replay all events (Event Sourcing).
        
        Returns:
            List of all events
        """
        return self.events.copy()