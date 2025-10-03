"""
Audit Logger - Event Sourcing pour traçabilité complète
"""
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum


class AuditEventType(Enum):
    SCRUB = "SCRUB"
    DESCRUB = "DESCRUB"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    CONFIG_CHANGED = "CONFIG_CHANGED"


class AuditLogger:
    """
    Event Sourcing pattern: append-only audit log
    Permet reconstruction complète de l'historique
    """
    
    def __init__(self, storage_path: str = "audit_events.jsonl"):
        self.storage_path = storage_path
        self.observers = []  # Observer pattern
        
    def register_observer(self, observer):
        """Register observer for real-time monitoring"""
        self.observers.append(observer)
        
    def _notify_observers(self, event: Dict):
        """Notify all observers of new event"""
        for observer in self.observers:
            observer.on_audit_event(event)
    
    def _create_event(self, event_type: AuditEventType, data: Dict) -> Dict:
        """Create standardized audit event"""
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type.value,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        }
        return event
    
    def _persist_event(self, event: Dict):
        """Append event to storage (append-only)"""
        with open(self.storage_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(event) + '\n')
    
    def log_scrub(self, user_id: str, original_text: str, 
                  scrubbed_text: str, entities: List[Dict]) -> str:
        """
        Log scrubbing operation
        Returns: event_id for traceability
        """
        event = self._create_event(AuditEventType.SCRUB, {
            "user_id": user_id,
            "original_length": len(original_text),
            "scrubbed_length": len(scrubbed_text),
            "entities_detected": len(entities),
            "entity_types": [e.get("entity", "UNKNOWN") for e in entities],
            "entities_detail": entities
        })
        
        self._persist_event(event)
        self._notify_observers(event)
        
        return event["event_id"]
    
    def log_descrub(self, user_id: str, restored_text: str, 
                    restored_entities: List[Dict], justification: str) -> str:
        """
        Log de-scrubbing operation (critical for compliance)
        Returns: event_id
        """
        event = self._create_event(AuditEventType.DESCRUB, {
            "user_id": user_id,
            "restored_length": len(restored_text),
            "entities_restored": len(restored_entities),
            "entity_types": [e.get("entity", "UNKNOWN") for e in restored_entities],
            "justification": justification,
            "entities_detail": restored_entities
        })
        
        self._persist_event(event)
        self._notify_observers(event)
        
        return event["event_id"]
    
    def log_access_decision(self, user_id: str, resource_id: str, 
                           granted: bool, reason: str) -> str:
        """Log access control decisions"""
        event_type = AuditEventType.ACCESS_GRANTED if granted else AuditEventType.ACCESS_DENIED
        
        event = self._create_event(event_type, {
            "user_id": user_id,
            "resource_id": resource_id,
            "reason": reason
        })
        
        self._persist_event(event)
        self._notify_observers(event)
        
        return event["event_id"]
    
    def get_events(self, event_type: Optional[AuditEventType] = None, 
                   user_id: Optional[str] = None, 
                   start_date: Optional[datetime] = None) -> List[Dict]:
        """
        Query audit events (pour analytics et compliance)
        """
        events = []
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                for line in f:
                    event = json.loads(line)
                    
                    # Apply filters
                    if event_type and event["event_type"] != event_type.value:
                        continue
                    if user_id and event["data"].get("user_id") != user_id:
                        continue
                    if start_date:
                        event_time = datetime.fromisoformat(event["timestamp"])
                        if event_time < start_date:
                            continue
                    
                    events.append(event)
        except FileNotFoundError:
            pass
        
        return events
    
    def get_statistics(self) -> Dict:
        """Generate audit statistics"""
        events = self.get_events()
        
        stats = {
            "total_events": len(events),
            "scrub_operations": 0,
            "descrub_operations": 0,
            "access_granted": 0,
            "access_denied": 0,
            "unique_users": set(),
            "total_entities_detected": 0,
            "total_entities_restored": 0
        }
        
        for event in events:
            event_type = event["event_type"]
            data = event["data"]
            
            if event_type == AuditEventType.SCRUB.value:
                stats["scrub_operations"] += 1
                stats["total_entities_detected"] += data.get("entities_detected", 0)
            elif event_type == AuditEventType.DESCRUB.value:
                stats["descrub_operations"] += 1
                stats["total_entities_restored"] += data.get("entities_restored", 0)
            elif event_type == AuditEventType.ACCESS_GRANTED.value:
                stats["access_granted"] += 1
            elif event_type == AuditEventType.ACCESS_DENIED.value:
                stats["access_denied"] += 1
            
            if "user_id" in data:
                stats["unique_users"].add(data["user_id"])
        
        stats["unique_users"] = len(stats["unique_users"])
        
        return stats


class MetricsObserver:
    """
    Observer pattern: real-time metrics collection
    """
    
    def __init__(self):
        self.metrics = {
            "scrub_count": 0,
            "descrub_count": 0,
            "entities_detected_total": 0,
            "entities_restored_total": 0,
            "access_denied_count": 0
        }
    
    def on_audit_event(self, event: Dict):
        """React to audit events in real-time"""
        event_type = event["event_type"]
        data = event["data"]
        
        if event_type == AuditEventType.SCRUB.value:
            self.metrics["scrub_count"] += 1
            self.metrics["entities_detected_total"] += data.get("entities_detected", 0)
        
        elif event_type == AuditEventType.DESCRUB.value:
            self.metrics["descrub_count"] += 1
            self.metrics["entities_restored_total"] += data.get("entities_restored", 0)
        
        elif event_type == AuditEventType.ACCESS_DENIED.value:
            self.metrics["access_denied_count"] += 1
    
    def get_metrics(self) -> Dict:
        return self.metrics.copy()


class AlertObserver:
    """
    Observer pattern: security alerting
    """
    
    def __init__(self, alert_threshold: int = 5):
        self.alert_threshold = alert_threshold
        self.descrub_attempts = {}  # user_id -> count
    
    def on_audit_event(self, event: Dict):
        """Detect suspicious patterns"""
        event_type = event["event_type"]
        data = event["data"]
        
        if event_type == AuditEventType.DESCRUB.value:
            user_id = data.get("user_id")
            self.descrub_attempts[user_id] = self.descrub_attempts.get(user_id, 0) + 1
            
            if self.descrub_attempts[user_id] >= self.alert_threshold:
                self._raise_alert(user_id, self.descrub_attempts[user_id])
    
    def _raise_alert(self, user_id: str, attempt_count: int):
        """Raise security alert (could send to SIEM, email, etc.)"""
        print(f" SECURITY ALERT: User {user_id} has made {attempt_count} descrub attempts!")
        # In production: send to monitoring system