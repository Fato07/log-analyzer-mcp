"""Log Analyzer MCP Server - Analyze and debug log files.

This MCP server provides 9 tools for intelligent log file analysis:
- log_analyzer_parse: Parse and detect log format
- log_analyzer_search: Search patterns with context
- log_analyzer_extract_errors: Extract errors with stack traces
- log_analyzer_summarize: Generate debugging summary
- log_analyzer_tail: Get recent log entries
- log_analyzer_correlate: Correlate events in time windows
- log_analyzer_diff: Compare log files or time periods
- log_analyzer_watch: Watch log files for new entries in real-time
- log_analyzer_suggest_patterns: Suggest useful search patterns
"""

__version__ = "0.2.0"

from codesdevs_log_analyzer.models import (
    Anomaly,
    FileInfo,
    LogFormat,
    LogLevel,
    ParsedLogEntry,
    ResponseFormat,
    TimeRange,
)
from codesdevs_log_analyzer.parsers import (
    PARSER_REGISTRY,
    detect_format,
    get_parser,
)
from codesdevs_log_analyzer.server import (
    log_analyzer_correlate,
    log_analyzer_diff,
    log_analyzer_extract_errors,
    log_analyzer_parse,
    log_analyzer_search,
    log_analyzer_suggest_patterns,
    log_analyzer_summarize,
    log_analyzer_tail,
    log_analyzer_watch,
    main,
    mcp,
)

__all__ = [
    # Version
    "__version__",
    # Server
    "mcp",
    "main",
    # Tools
    "log_analyzer_parse",
    "log_analyzer_search",
    "log_analyzer_extract_errors",
    "log_analyzer_summarize",
    "log_analyzer_tail",
    "log_analyzer_correlate",
    "log_analyzer_diff",
    "log_analyzer_watch",
    "log_analyzer_suggest_patterns",
    # Models
    "LogFormat",
    "ResponseFormat",
    "LogLevel",
    "ParsedLogEntry",
    "FileInfo",
    "TimeRange",
    "Anomaly",
    # Parser functions
    "detect_format",
    "get_parser",
    "PARSER_REGISTRY",
]
