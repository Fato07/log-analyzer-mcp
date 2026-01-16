# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-16

### Added

- **New Tools**
  - `log_analyzer_watch` - Watch log files for new entries using position-based polling
    - Real-time monitoring with level and pattern filtering
    - Position tracking for efficient incremental reads
    - Supports level filtering (`ERROR`, `WARN,ERROR`, etc.)
    - Supports regex pattern filtering
  - `log_analyzer_suggest_patterns` - AI-powered pattern suggestions for debugging
    - Analyzes log content to suggest useful search patterns
    - Focus modes: `all`, `errors`, `security`, `performance`, `identifiers`
    - Detects UUIDs, IPs, error templates, security indicators
    - Priority-ranked suggestions (high/medium/low)

- **New Analyzers**
  - `LogWatcher` class for position-based log watching
  - `PatternSuggester` class for pattern analysis and suggestions
  - `WatchResult`, `SuggestedPattern`, `PatternSuggestionResult` dataclasses

### Changed

- Total tools increased from 7 to 9
- Test suite expanded from 248 to 280 tests
- Updated documentation with new tool examples and parameters

## [0.1.0] - 2026-01-16

### Added

- **MCP Server Implementation**
  - FastMCP-based server with 7 log analysis tools
  - Full MCP protocol compliance for AI assistant integration

- **Log Analysis Tools**
  - `log_analyzer_parse` - Parse and detect log format with metadata extraction
  - `log_analyzer_search` - Pattern search with context lines and regex support
  - `log_analyzer_extract_errors` - Extract and group errors with stack traces
  - `log_analyzer_summarize` - Generate debugging summaries with statistics
  - `log_analyzer_tail` - Get recent log entries with filtering
  - `log_analyzer_correlate` - Correlate events within time windows
  - `log_analyzer_diff` - Compare log files or time periods

- **Log Format Parsers**
  - Syslog format parser
  - Apache/Nginx access log parser (combined format)
  - Apache/Nginx error log parser
  - JSON Lines (JSONL) structured log parser
  - Python logging format parser
  - Java/Log4j format parser
  - Docker container log parser
  - Kubernetes pod log parser
  - Generic timestamp fallback parser

- **Analysis Features**
  - Automatic log format detection with confidence scoring
  - Error grouping by normalized message templates
  - Stack trace detection and extraction
  - Pattern matching with context windows
  - Time-based event correlation
  - Performance metrics and security indicators

- **Utilities**
  - Streaming file operations for memory efficiency
  - Automatic encoding detection with chardet
  - Gzip compression support
  - Flexible timestamp parsing
  - Markdown and JSON output formatting

- **Developer Experience**
  - Comprehensive test suite with 248 tests
  - 81%+ code coverage
  - Type hints throughout with mypy --strict compliance
  - Ruff linting with zero errors
  - Sample log files for testing

### Technical Details

- Python 3.10+ support
- Pydantic v2 for data validation
- Memory-efficient streaming for large files (100MB+)
- Sub-10 second processing for 100MB files

[0.2.0]: https://github.com/codesdevs/log-analyzer-mcp/releases/tag/v0.2.0
[0.1.0]: https://github.com/codesdevs/log-analyzer-mcp/releases/tag/v0.1.0
