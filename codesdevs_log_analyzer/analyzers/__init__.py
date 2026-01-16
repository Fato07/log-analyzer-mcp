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
from codesdevs_log_analyzer.analyzers.multi_file import (
    CorrelationCluster,
    MultiFileAnalyzer,
    MultiFileEntry,
    MultiFileResult,
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
from codesdevs_log_analyzer.analyzers.query_translator import (
    QueryIntent,
    QueryResult,
    QueryTranslator,
)
from codesdevs_log_analyzer.analyzers.recommendation_engine import (
    CausalChain,
    CausalChainLink,
    RecommendationEngine,
)
from codesdevs_log_analyzer.analyzers.sensitive_detector import (
    SensitiveDataDetector,
    SensitiveDataResult,
    SensitiveMatch,
)
from codesdevs_log_analyzer.analyzers.summarizer import (
    LogSummary,
    PerformanceMetrics,
    SecurityIndicators,
    Summarizer,
)
from codesdevs_log_analyzer.analyzers.trace_extractor import (
    TraceEntry,
    TraceExtractionResult,
    TraceExtractor,
    TraceGroup,
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
    # Trace extraction
    "TraceExtractor",
    "TraceEntry",
    "TraceGroup",
    "TraceExtractionResult",
    # Multi-file analysis
    "MultiFileAnalyzer",
    "MultiFileEntry",
    "MultiFileResult",
    "CorrelationCluster",
    # Recommendation engine
    "RecommendationEngine",
    "CausalChain",
    "CausalChainLink",
    # Query translator
    "QueryTranslator",
    "QueryIntent",
    "QueryResult",
    # Sensitive data detection
    "SensitiveDataDetector",
    "SensitiveDataResult",
    "SensitiveMatch",
]
