"""Analyzer modules for log processing."""

from mcp_log_analyzer.analyzers.correlator import (
    CorrelationResult,
    CorrelationWindow,
    Correlator,
    StreamingCorrelator,
)
from mcp_log_analyzer.analyzers.error_extractor import (
    ErrorExtractionResult,
    ErrorExtractor,
    ErrorGroup,
)
from mcp_log_analyzer.analyzers.pattern_matcher import (
    PatternMatcher,
    SearchMatch,
    SearchResult,
)
from mcp_log_analyzer.analyzers.summarizer import (
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
