"""Analyzer modules for log processing."""

from codesdevs_log_analyzer.analyzers.correlator import (
    CorrelationResult,
    CorrelationWindow,
    Correlator,
    StreamingCorrelator,
)
from codesdevs_log_analyzer.analyzers.error_extractor import (
    ErrorExtractionResult,
    ErrorExtractor,
    ErrorGroup,
)
from codesdevs_log_analyzer.analyzers.log_watcher import (
    LogWatcher,
    WatchResult,
)
from codesdevs_log_analyzer.analyzers.pattern_matcher import (
    PatternMatcher,
    SearchMatch,
    SearchResult,
)
from codesdevs_log_analyzer.analyzers.pattern_suggester import (
    PatternSuggester,
    PatternSuggestionResult,
    SuggestedPattern,
)
from codesdevs_log_analyzer.analyzers.summarizer import (
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
    # Log watching
    "LogWatcher",
    "WatchResult",
    # Pattern suggestion
    "PatternSuggester",
    "PatternSuggestionResult",
    "SuggestedPattern",
]
