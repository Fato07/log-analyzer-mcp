"""Analyzer modules for log processing."""

from log_analyzer_mcp.analyzers.correlator import (
    CorrelationResult,
    CorrelationWindow,
    Correlator,
    StreamingCorrelator,
)
from log_analyzer_mcp.analyzers.error_extractor import (
    ErrorExtractionResult,
    ErrorExtractor,
    ErrorGroup,
)
from log_analyzer_mcp.analyzers.pattern_matcher import (
    PatternMatcher,
    SearchMatch,
    SearchResult,
)
from log_analyzer_mcp.analyzers.summarizer import (
    LogSummary,
    PerformanceMetrics,
    SecurityIndicators,
    Summarizer,
)

__all__ = [
    # Error extraction
    "ErrorExtractor",
    "ErrorGroup",
    "ErrorExtractionResult",
    # Pattern matching
    "PatternMatcher",
    "SearchMatch",
    "SearchResult",
    # Summarization
    "Summarizer",
    "LogSummary",
    "PerformanceMetrics",
    "SecurityIndicators",
    # Correlation
    "Correlator",
    "CorrelationWindow",
    "CorrelationResult",
    "StreamingCorrelator",
]
