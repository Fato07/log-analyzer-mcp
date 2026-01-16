# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-01-16

### Added

- Published to official MCP Registry at https://registry.modelcontextprotocol.io
- Added MCP Registry badge to README
- Added `mcp-name` comment to README for registry validation

### Changed

- Fixed mcp-name case to match GitHub username exactly (Fato07)

## [0.4.1] - 2026-01-16

### Added

- Added `mcp-name` comment to README for MCP Registry validation
- Created `server.json` for MCP Registry publishing
- Added `[tool.mcp]` section to pyproject.toml

## [0.4.0] - 2026-01-16

### Added

- Release automation with Makefile and scripts/release.py
- Added `release.sh` wrapper script for version bumping

## [0.3.1] - 2026-01-16

### Changed

- **MCP Best Practices Compliance**
  - Server name changed from `log-analyzer-mcp` to `log_analyzer_mcp` (Python naming convention)
  - All 14 tools now include `ToolAnnotations` with proper hints:
    - `readOnlyHint=True` - All tools are read-only operations
    - `destructiveHint=False` - No tools modify log files
    - `idempotentHint=True/False` - Properly indicates if results are consistent
    - `openWorldHint=False` - Tools don't interact with external systems
  - Enhanced server instructions with comprehensive description
  - Added `title` property to all tool annotations for better discoverability

### Technical

- Import `ToolAnnotations` from `mcp.types` for proper MCP protocol compliance
- All 280 tests passing
- mypy strict mode passing
- ruff linting passing

## [0.3.0] - 2026-01-16

### Added

- **New Tools**
  - `log_analyzer_trace` - Extract and follow trace/correlation IDs across log entries
    - Auto-detects trace ID formats (OpenTelemetry, UUID, AWS X-Ray, custom patterns)
    - Groups entries by trace ID to show complete request flows
    - Identifies traces containing errors
    - Calculates trace duration and entry counts
  - `log_analyzer_multi` - Analyze and correlate logs across multiple files
    - **Merge**: Interleave entries from multiple files by timestamp
    - **Correlate**: Find events happening across files within time windows
    - **Compare**: Diff error patterns and statistics between files
  - `log_analyzer_ask` - Natural language query translation
    - Translates questions like "what errors happened today?" into tool calls
    - Detects query intent (search, count, analyze, find_cause, compare)
    - Identifies focus area (errors, security, performance, network)
    - Extracts time references ("last hour", "today", "yesterday")
    - Generates follow-up suggestions
  - `log_analyzer_scan_sensitive` - Sensitive data detection for security auditing
    - **PII Detection**: Emails, credit cards (Visa/MC/Amex), SSNs, phone numbers
    - **Credential Detection**: API keys, JWT tokens, AWS keys, Bearer tokens
    - **Secret Detection**: Passwords in URLs, private keys, database connection strings
    - Severity categorization (high/medium/low)
    - Optional redaction mode
  - `log_analyzer_suggest_format` - Suggest log format based on content analysis

- **New Analyzers**
  - `TraceExtractor` class for trace ID extraction and correlation
  - `MultiFileAnalyzer` class for multi-file operations
  - `QueryTranslator` class for natural language query translation
  - `SensitiveDataDetector` class for PII and credential detection
  - `RecommendationEngine` class for actionable recommendations

### Enhanced

- **Summarizer Enhancements**
  - Security analysis section: Failed auth attempts, brute force indicators, SQL injection attempts, XSS attempts, suspicious user agents
  - Performance metrics section with timing and throughput analysis

### Changed

- Total tools increased from 9 to 14
- Test suite remains at 280 tests (all passing)
- Updated documentation with new tool examples and parameters

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

[0.3.1]: https://github.com/codesdevs/log-analyzer-mcp/releases/tag/v0.3.1
[0.3.0]: https://github.com/codesdevs/log-analyzer-mcp/releases/tag/v0.3.0
[0.2.0]: https://github.com/codesdevs/log-analyzer-mcp/releases/tag/v0.2.0
[0.1.0]: https://github.com/codesdevs/log-analyzer-mcp/releases/tag/v0.1.0
