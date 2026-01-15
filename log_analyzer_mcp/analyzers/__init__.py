"""Log analyzers for extracting insights from parsed logs."""

from .error_extractor import (
    ErrorExtractor,
    ErrorExtractionResult,
    ErrorGroup,
    extract_errors,
    normalize_error_message,
    MAX_ERRORS,
    MAX_SAMPLE_ENTRIES,
    MAX_STACK_TRACE_LINES,
)

from .pattern_matcher import (
    PatternMatcher,
    SearchMatch,
    SearchResult,
    search_pattern,
    MAX_MATCHES,
    MAX_CONTEXT_LINES,
)

from .summarizer import (
    Summarizer,
    LogSummary,
    PerformanceMetrics,
    SecurityIndicators,
    summarize_log,
    MAX_TOP_ERRORS,
    MAX_ANOMALIES,
)

from .correlator import (
    Correlator,
    StreamingCorrelator,
    CorrelationWindow,
    CorrelationResult,
    correlate_events,
    MAX_ANCHORS,
    MAX_EVENTS_PER_WINDOW,
    MAX_PRECURSORS,
)


__all__ = [
    # Error Extractor
    "ErrorExtractor",
    "ErrorExtractionResult",
    "ErrorGroup",
    "extract_errors",
    "normalize_error_message",
    "MAX_ERRORS",
    "MAX_SAMPLE_ENTRIES",
    "MAX_STACK_TRACE_LINES",
    # Pattern Matcher
    "PatternMatcher",
    "SearchMatch",
    "SearchResult",
    "search_pattern",
    "MAX_MATCHES",
    "MAX_CONTEXT_LINES",
    # Summarizer
    "Summarizer",
    "LogSummary",
    "PerformanceMetrics",
    "SecurityIndicators",
    "summarize_log",
    "MAX_TOP_ERRORS",
    "MAX_ANOMALIES",
    # Correlator
    "Correlator",
    "StreamingCorrelator",
    "CorrelationWindow",
    "CorrelationResult",
    "correlate_events",
    "MAX_ANCHORS",
    "MAX_EVENTS_PER_WINDOW",
    "MAX_PRECURSORS",
]
