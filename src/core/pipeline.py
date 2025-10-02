"""
Chain of Responsibility pipeline for scrubbing.
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from datetime import datetime
import hashlib

from .entities import ScrubResult, DetectedEntity


class ScrubberLink(ABC):
    """
    Abstract link in the scrubbing chain.
    
    Each link processes content and passes to the next link.
    Observers can be attached for audit purposes.
    """
    
    def __init__(self):
        self._next: Optional['ScrubberLink'] = None
        self._observers: List['AuditObserver'] = []
    
    def set_next(self, handler: 'ScrubberLink') -> 'ScrubberLink':
        """
        Set the next handler in the chain.
        
        Args:
            handler: Next link to process
            
        Returns:
            The handler (for chaining)
        """
        self._next = handler
        return handler
    
    def attach_observer(self, observer: 'AuditObserver'):
        """Attach an audit observer."""
        self._observers.append(observer)
    
    def notify_observers(self, event: 'AuditEvent'):
        """Notify all observers of an event."""
        for observer in self._observers:
            observer.update(event)
    
    @abstractmethod
    def process(self, content: str, context: Dict[str, Any]) -> ScrubResult:
        """
        Process the content.
        
        Args:
            content: Content to process
            context: Processing context
            
        Returns:
            ScrubResult with processing outcome
        """
        pass
    
    def handle(self, content: str, context: Dict[str, Any]) -> ScrubResult:
        """
        Main handler method - processes and chains.
        
        Args:
            content: Content to process
            context: Processing context
            
        Returns:
            Final ScrubResult after full chain
        """
        # Process at this link
        result = self.process(content, context)
        
        # Notify observers
        from ..audit.observers import AuditEvent
        event = AuditEvent(
            event_type="scrubbing",
            handler=self.__class__.__name__,
            result=result,
            context=context,
            timestamp=datetime.now()
        )
        self.notify_observers(event)
        
        # Chain to next if exists
        if self._next:
            # Update context with current results
            context['previous_entities'] = result.entities
            return self._next.handle(result.scrubbed_content, context)
        
        return result


class PreProcessorLink(ScrubberLink):
    """
    Pre-processes content to prevent bypass attempts.
    
    Normalizes unicode, detects obfuscation, etc.
    """
    
    def process(self, content: str, context: Dict[str, Any]) -> ScrubResult:
        """
        Pre-process content.
        
        Args:
            content: Content to pre-process
            context: Processing context
            
        Returns:
            ScrubResult with normalized content
        """
        # Unicode normalization
        import unicodedata
        normalized = unicodedata.normalize('NFKC', content)
        
        # Remove zero-width characters (common obfuscation)
        zero_width_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF']
        for char in zero_width_chars:
            normalized = normalized.replace(char, '')
        
        # TODO: Add bypass detection patterns
        
        return ScrubResult(
            scrubbed_content=normalized,
            entities=[],
            timestamp=datetime.now(),
            session_id=context.get('session_id', ''),
            confidence_score=1.0,
            metadata={'step': 'preprocessing'}
        )


class EntityDetectionLink(ScrubberLink):
    """
    Detects sensitive entities using a configured strategy.
    """
    
    def __init__(self, strategy: 'ScrubStrategy'):
        super().__init__()
        self.strategy = strategy
    
    def process(self, content: str, context: Dict[str, Any]) -> ScrubResult:
        """
        Detect entities using strategy.
        
        Args:
            content: Content to analyze
            context: Processing context
            
        Returns:
            ScrubResult with detected entities
        """
        result = self.strategy.scrub(content, context)
        
        # Store entities in context for next links
        context['detected_entities'] = result.entities
        
        return result
    
    def set_strategy(self, strategy: 'ScrubStrategy'):
        """Dynamically change detection strategy."""
        self.strategy = strategy


class ReplacementLink(ScrubberLink):
    """
    Replaces detected entities with contextual tokens.
    """
    
    def process(self, content: str, context: Dict[str, Any]) -> ScrubResult:
        """
        Replace entities in content.
        
        Args:
            content: Content with entities to replace
            context: Must contain 'detected_entities'
            
        Returns:
            ScrubResult with entities replaced
        """
        entities = context.get('detected_entities', [])
        
        if not entities:
            return ScrubResult(
                scrubbed_content=content,
                entities=[],
                timestamp=datetime.now(),
                session_id=context.get('session_id', ''),
                confidence_score=1.0,
                metadata={'step': 'replacement'}
            )
        
        # Sort entities by position (reverse) to maintain positions
        sorted_entities = sorted(entities, key=lambda e: e.start_pos, reverse=True)
        
        scrubbed = content
        for entity in sorted_entities:
            token = entity.get_replacement_token()
            scrubbed = (
                scrubbed[:entity.start_pos] + 
                token + 
                scrubbed[entity.end_pos:]
            )
        
        return ScrubResult(
            scrubbed_content=scrubbed,
            entities=entities,
            timestamp=datetime.now(),
            session_id=context.get('session_id', ''),
            confidence_score=self._calculate_confidence(entities),
            metadata={'step': 'replacement'}
        )
    
    def _calculate_confidence(self, entities: List[DetectedEntity]) -> float:
        """Calculate overall confidence from entities."""
        if not entities:
            return 1.0
        return sum(e.confidence for e in entities) / len(entities)


class ScrubberPipeline:
    """
    Orchestrates the scrubbing pipeline.
    
    Builds and executes a chain of scrubber links.
    """
    
    def __init__(self):
        self.head: Optional[ScrubberLink] = None
        self.links: List[ScrubberLink] = []
    
    def build(self, links: List[ScrubberLink]) -> 'ScrubberPipeline':
        """
        Build the pipeline from a list of links.
        
        Args:
            links: List of ScrubberLink instances
            
        Returns:
            Self for chaining
        """
        if not links:
            raise ValueError("Cannot build empty pipeline")
        
        self.head = links[0]
        self.links = links
        
        # Chain links together
        for i in range(len(links) - 1):
            links[i].set_next(links[i + 1])
        
        return self
    
    def execute(self, content: str, context: Dict[str, Any] = None) -> ScrubResult:
        """
        Execute the full pipeline.
        
        Args:
            content: Content to scrub
            context: Processing context
            
        Returns:
            Final ScrubResult
        """
        if not self.head:
            raise ValueError("Pipeline not built. Call build() first.")
        
        context = context or {}
        
        # Generate session ID if not provided
        if 'session_id' not in context:
            context['session_id'] = self._generate_session_id()
        
        # Store original content
        context['original_content'] = content
        
        # Execute pipeline
        result = self.head.handle(content, context)
        
        # Add original content to result
        result.original_content = content
        
        return result
    
    @staticmethod
    def _generate_session_id() -> str:
        """Generate unique session ID."""
        timestamp = datetime.now().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]