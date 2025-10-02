"""
Tests for pipeline architecture.
"""
import pytest
from datetime import datetime

from src.core.pipeline import (
    ScrubberPipeline, PreProcessorLink, 
    EntityDetectionLink, ReplacementLink
)
from src.core.entities import DetectedEntity, EntityType, ConfidentialityLevel
from src.strategies.regex_strategy import RegexStrategy


class TestScrubberPipeline:
    """Test suite for scrubbing pipeline."""
    
    @pytest.fixture
    def pipeline(self):
        """Create a test pipeline."""
        strategy = RegexStrategy()
        return ScrubberPipeline().build([
            PreProcessorLink(),
            EntityDetectionLink(strategy),
            ReplacementLink()
        ])
    
    def test_pipeline_execution(self, pipeline):
        """Test basic pipeline execution."""
        content = "Transfer to IBAN BE68539007547034"
        result = pipeline.execute(content)
        
        assert result is not None
        assert result.session_id
        assert len(result.session_id) == 16
    
    def test_iban_detection_and_replacement(self, pipeline):
        """Test IBAN is detected and replaced."""
        content = "IBAN: BE68539007547034"
        result = pipeline.execute(content)
        
        # Should detect IBAN
        assert len(result.entities) > 0
        iban_entities = [
            e for e in result.entities 
            if e.entity_type == EntityType.IBAN
        ]
        assert len(iban_entities) == 1
        
        # Should replace in content
        assert "BE68539007547034" not in result.scrubbed_content
        assert "[IBAN_" in result.scrubbed_content
    
    def test_multiple_entities(self, pipeline):
        """Test detection of multiple entity types."""
        content = """
        Contact: john@example.com
        Phone: +32471234567
        IBAN: BE68539007547034
        """
        result = pipeline.execute(content)
        
        # Should detect multiple entities
        assert len(result.entities) >= 3
        
        # Check all types detected
        types = {e.entity_type for e in result.entities}
        assert EntityType.EMAIL in types
        assert EntityType.PHONE in types
        assert EntityType.IBAN in types
    
    def test_no_false_positives(self, pipeline):
        """Test that normal text doesn't trigger detection."""
        content = "This is just normal text without sensitive data."
        result = pipeline.execute(content)
        
        assert len(result.entities) == 0
        assert result.scrubbed_content == content