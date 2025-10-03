"""
Unit Tests for SecurePrompt
Run with: pytest test_secureprompt.py -v
"""
import pytest
import os
import tempfile
from datetime import datetime

from src.api.scrubber import Scrubber, YAMLRuleStrategy, RegexPatternsStrategy, SpacyNERStrategy
from src.api.descrubber import DeScrubber, AccessControlPolicy, AccessLevel, SecureVault
from src.audit.audit import AuditLogger, MetricsObserver, AlertObserver, AuditEventType


# ============================================
# Fixtures
# ============================================
@pytest.fixture
def temp_audit_file():
    """Create temporary audit file"""
    fd, path = tempfile.mkstemp(suffix='.jsonl')
    os.close(fd)
    yield path
    os.unlink(path)


@pytest.fixture
def audit_logger(temp_audit_file):
    """Create audit logger with temp file"""
    return AuditLogger(temp_audit_file)


@pytest.fixture
def scrubber(audit_logger):
    """Create scrubber instance"""
    return Scrubber(
        rules_yaml="rules.yaml",
        whitelist_yaml="whitelist.yaml",
        audit_logger=audit_logger
    )


@pytest.fixture
def descrubber(audit_logger):
    """Create descrubber instance"""
    return DeScrubber(audit_logger=audit_logger)


# ============================================
# Scrubber Tests
# ============================================
class TestScrubber:
    
    def test_email_detection(self, scrubber):
        """Test email detection"""
        text = "Contact me at john.doe@example.com"
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        
        assert len(entities) == 1
        assert entities[0]['entity'] == 'Email'
        assert entities[0]['value'] == 'john.doe@example.com'
        assert '{{Email' in scrubbed_text
    
    def test_phone_detection(self, scrubber):
        """Test phone number detection"""
        text = "Call me at +32-2-123-4567"
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        
        assert len(entities) == 1
        assert entities[0]['entity'] == 'Phone Number'
        assert '+32-2-123-4567' in entities[0]['value']
    
    def test_iban_detection(self, scrubber):
        """Test IBAN detection"""
        text = "My IBAN: BE71 0961 2345 6769"
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        
        assert len(entities) >= 1
        iban_found = any(e['entity'] == 'IBAN' for e in entities)
        assert iban_found
    
    def test_credit_card_detection(self, scrubber):
        """Test credit card detection"""
        text = "Card: 4532-1234-5678-9010"
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        
        assert len(entities) >= 1
        cc_found = any('Credit' in e['entity'] for e in entities)
        assert cc_found
    
    def test_whitelist(self, scrubber):
        """Test whitelist functionality"""
        text = "Contact support@company.com"  # This is in whitelist
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        
        # Should not scrub whitelisted email
        assert 'support@company.com' in scrubbed_text
    
    def test_multiple_entities(self, scrubber):
        """Test detection of multiple entities"""
        text = "Email: john@example.com, Phone: +1-555-0123, IBAN: BE71 0961 2345 6769"
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        
        assert len(entities) >= 3
        assert 'john@example.com' not in scrubbed_text
    
    def test_entity_enrichment(self, scrubber):
        """Test entity enrichment with metadata"""
        text = "My email is test@example.com"
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        
        entity = entities[0]
        assert 'id' in entity
        assert 'entity' in entity
        assert 'value' in entity
        assert 'classification' in entity
        assert 'confidence' in entity
        assert 'explanation' in entity


# ============================================
# Detection Strategy Tests
# ============================================
class TestDetectionStrategies:
    
    def test_yaml_strategy(self):
        """Test YAML rule strategy"""
        rules = [{
            "column": "Test_Entity",
            "detection": {
                "type": "regex",
                "pattern": r"TEST-\d{4}"
            },
            "priority": 1
        }]
        
        strategy = YAMLRuleStrategy(rules)
        entities = strategy.detect("Code: TEST-1234", set())
        
        assert len(entities) == 1
        assert entities[0]['value'] == 'TEST-1234'
    
    def test_regex_strategy(self):
        """Test regex patterns strategy"""
        strategy = RegexPatternsStrategy()
        entities = strategy.detect("Email: test@example.com", set())
        
        assert len(entities) == 1
        assert entities[0]['entity'] == 'Email'


# ============================================
# DeScrubber Tests
# ============================================
class TestDeScrubber:
    
    def test_store_and_retrieve(self, descrubber):
        """Test storing and retrieving placeholders"""
        entities = [
            {
                "id": "{{Email_1}}",
                "value": "test@example.com",
                "classification": "C2",
                "explanation": "test"
            }
        ]
        
        descrubber.store_placeholders(entities)
        
        assert descrubber.vault.exists("{{Email_1}}")
        retrieved = descrubber.vault.retrieve("{{Email_1}}")
        assert retrieved['value'] == 'test@example.com'
    
    def test_descrub_with_permissions(self, descrubber, audit_logger):
        """Test de-scrubbing with access control"""
        entities = [
            {
                "id": "{{Email_1}}",
                "entity": "Email",
                "value": "test@example.com",
                "classification": "C2",
                "explanation": "test"
            }
        ]
        
        descrubber.store_placeholders(entities)
        
        scrubbed_text = "Contact {{Email_1}}"
        
        # Test with security_admin (should have access)
        restored, restored_ents, audit_id, denied = descrubber.descrub(
            scrubbed_text=scrubbed_text,
            requested_placeholders=["{{Email_1}}"],
            user_id="admin",
            user_role="security_admin",
            justification="Test"
        )
        
        assert "test@example.com" in restored
        assert len(denied) == 0
    
    def test_access_denied(self, descrubber):
        """Test access denial for sensitive data"""
        entities = [
            {
                "id": "{{SSN_1}}",
                "entity": "SSN",
                "value": "123-45-6789",
                "classification": "C4",
                "explanation": "test"
            }
        ]
        
        descrubber.store_placeholders(entities)
        
        # Test with data_analyst (should NOT have access to SSN)
        scrubbed_text = "SSN: {{SSN_1}}"
        restored, restored_ents, audit_id, denied = descrubber.descrub(
            scrubbed_text=scrubbed_text,
            requested_placeholders=["{{SSN_1}}"],
            user_id="analyst",
            user_role="data_analyst",
            justification="Test"
        )
        
        assert len(denied) == 1
        assert "123-45-6789" not in restored
    
    def test_partial_descrub(self, descrubber):
        """Test partial de-scrubbing with masking"""
        entities = [
            {
                "id": "{{Email_1}}",
                "entity": "Email",
                "value": "john@example.com",
                "classification": "C2",
                "explanation": "test"
            }
        ]
        
        descrubber.store_placeholders(entities)
        
        scrubbed_text = "Email: {{Email_1}}"
        
        restored, restored_ents, audit_id = descrubber.partial_descrub(
            scrubbed_text=scrubbed_text,
            requested_placeholders=["{{Email_1}}"],
            user_id="analyst",
            user_role="data_analyst",
            justification="Test",
            mask_method="partial"
        )
        
        assert "jo***@example.com" in restored
        assert "john@example.com" not in restored


# ============================================
# Access Control Tests
# ============================================
class TestAccessControl:
    
    def test_default_policies(self):
        """Test default access control policies"""
        policy = AccessControlPolicy()
        
        # Security admin should access everything
        assert policy.can_access("security_admin", "Email")
        assert policy.can_access("security_admin", "SSN")
        
        # Data analyst should not access SSN
        assert not policy.can_access("data_analyst", "SSN")
    
    def test_custom_role(self):
        """Test adding custom role"""
        policy = AccessControlPolicy()
        policy.add_role("custom_role", AccessLevel.PARTIAL)
        
        assert "custom_role" in policy.role_permissions
        assert policy.role_permissions["custom_role"] == AccessLevel.PARTIAL
    
    def test_entity_restriction(self):
        """Test entity-level restrictions"""
        policy = AccessControlPolicy()
        policy.restrict_entity("Custom_Entity", [AccessLevel.ADMIN])
        
        assert not policy.can_access("security_admin", "Custom_Entity")
        assert policy.can_access("system_admin", "Custom_Entity")


# ============================================
# Audit Tests
# ============================================
class TestAudit:
    
    def test_audit_logging(self, audit_logger):
        """Test audit event logging"""
        audit_id = audit_logger.log_scrub(
            user_id="test_user",
            original_text="test text",
            scrubbed_text="scrubbed",
            entities=[]
        )
        
        assert audit_id is not None
        
        events = audit_logger.get_events()
        assert len(events) == 1
        assert events[0]['event_type'] == 'SCRUB'
    
    def test_audit_filtering(self, audit_logger):
        """Test filtering audit events"""
        # Log different events
        audit_logger.log_scrub("user1", "text", "scrubbed", [])
        audit_logger.log_descrub("user2", "restored", [], "justification")
        
        # Filter by user
        events = audit_logger.get_events(user_id="user1")
        assert len(events) == 1
        assert events[0]['data']['user_id'] == 'user1'
        
        # Filter by event type
        events = audit_logger.get_events(event_type=AuditEventType.DESCRUB)
        assert len(events) == 1
        assert events[0]['event_type'] == 'DESCRUB'
    
    def test_audit_statistics(self, audit_logger):
        """Test audit statistics generation"""
        audit_logger.log_scrub("user1", "text", "scrubbed", [{"entity": "Email"}])
        audit_logger.log_descrub("user2", "restored", [{"entity": "Email"}], "test")
        
        stats = audit_logger.get_statistics()
        
        assert stats['total_events'] == 2
        assert stats['scrub_operations'] == 1
        assert stats['descrub_operations'] == 1
        assert stats['unique_users'] == 2


# ============================================
# Observer Pattern Tests
# ============================================
class TestObservers:
    
    def test_metrics_observer(self, audit_logger):
        """Test metrics observer"""
        metrics_observer = MetricsObserver()
        audit_logger.register_observer(metrics_observer)
        
        # Trigger events
        audit_logger.log_scrub("user1", "text", "scrubbed", [{"entity": "Email"}])
        
        metrics = metrics_observer.get_metrics()
        assert metrics['scrub_count'] == 1
        assert metrics['entities_detected_total'] == 1
    
    def test_alert_observer(self, audit_logger):
        """Test alert observer"""
        alert_observer = AlertObserver(alert_threshold=2)
        audit_logger.register_observer(alert_observer)
        
        # Trigger multiple de-scrub attempts
        for i in range(3):
            audit_logger.log_descrub("suspicious_user", "text", [], "test")
        
        assert alert_observer.descrub_attempts["suspicious_user"] == 3


# ============================================
# Integration Tests
# ============================================
class TestIntegration:
    
    def test_complete_workflow(self, scrubber, descrubber):
        """Test complete scrub -> store -> descrub workflow"""
        # Step 1: Scrub
        original_text = "My email is john@example.com and phone is +1-555-0123"
        scrubbed_text, entities = scrubber.scrub_text(original_text, user_id="test")
        
        assert len(entities) >= 2
        assert "john@example.com" not in scrubbed_text
        
        # Step 2: Store
        descrubber.store_placeholders(entities)
        
        # Step 3: De-scrub
        placeholder_ids = [e['id'] for e in entities]
        restored, restored_ents, audit_id, denied = descrubber.descrub(
            scrubbed_text=scrubbed_text,
            requested_placeholders=placeholder_ids,
            user_id="admin",
            user_role="security_admin",
            justification="Test workflow"
        )
        
        # Verify restoration
        assert "john@example.com" in restored
        assert "+1-555-0123" in restored


# ============================================
# Performance Tests
# ============================================
class TestPerformance:
    
    def test_large_text_scrubbing(self, scrubber):
        """Test scrubbing performance on large text"""
        import time
        
        # Create large text with multiple entities
        text = " ".join([
            f"User{i} email: user{i}@example.com phone: +1-555-{i:04d}"
            for i in range(100)
        ])
        
        start = time.time()
        scrubbed_text, entities = scrubber.scrub_text(text, user_id="test")
        duration = time.time() - start
        
        assert len(entities) >= 200  # 100 emails + 100 phones
        assert duration < 5.0  # Should complete in under 5 seconds
    
    def test_concurrent_scrubbing(self, scrubber):
        """Test concurrent scrubbing operations"""
        import threading
        
        results = []
        
        def scrub_task(text, user_id):
            scrubbed, entities = scrubber.scrub_text(text, user_id=user_id)
            results.append((scrubbed, entities))
        
        threads = []
        for i in range(10):
            text = f"Email: user{i}@example.com"
            thread = threading.Thread(target=scrub_task, args=(text, f"user{i}"))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        assert len(results) == 10


# ============================================
# Run Tests
# ============================================
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])