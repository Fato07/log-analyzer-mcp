# Log Analyzer MCP Server - Specification

## Overview

A Model Context Protocol (MCP) server that helps AI assistants analyze, parse, and debug log files across various formats. Designed to handle large log files efficiently and provide intelligent insights for debugging.

## Problem Statement

When debugging with AI assistants:
1. Log files are often too large to paste into context
2. Different applications use different log formats
3. Finding relevant error patterns requires domain knowledge
4. Correlating events across time is tedious

## Target Users

- Developers debugging application issues with Claude Code or similar AI tools
- DevOps engineers analyzing system logs
- Anyone who needs AI assistance with log analysis

## Core Features

### 1. Log Format Detection & Parsing

Automatically detect and parse common log formats:

| Format | Pattern Example | Use Case |
|--------|----------------|----------|
| **Syslog** | `Jan 15 10:30:00 hostname process[pid]: message` | Linux system logs |
| **Apache/Nginx Access** | `127.0.0.1 - - [15/Jan/2026:10:30:00 +0000] "GET /path HTTP/1.1" 200 1234` | Web server access |
| **Apache/Nginx Error** | `[Thu Jan 15 10:30:00.123456 2026] [error] [pid 1234] message` | Web server errors |
| **JSON Lines (JSONL)** | `{"timestamp": "...", "level": "ERROR", "message": "..."}` | Structured logging |
| **Docker/Container** | `2026-01-15T10:30:00.123456789Z stdout message` | Container logs |
| **Python Logging** | `2026-01-15 10:30:00,123 - module - ERROR - message` | Python apps |
| **Java/Log4j** | `2026-01-15 10:30:00,123 ERROR [thread] class - message` | Java apps |
| **Kubernetes** | `2026-01-15T10:30:00.123Z level=error msg="..."` | K8s logs |
| **Generic Timestamp** | Any line starting with ISO8601 or common date formats | Fallback |
| **Plain Text** | Lines without clear structure | Raw logs |

### 2. Tools

#### `log_analyzer_parse`
Parse and structure a log file, extracting metadata.

**Input:**
- `file_path` (str): Path to log file
- `format_hint` (str, optional): Force specific format detection
- `max_lines` (int, optional): Limit lines to parse (default: 10000)

**Output:**
- Detected format
- Total lines / parsed lines
- Time range (start/end timestamps)
- Log level distribution (if applicable)
- Sample entries (first 5, last 5)

#### `log_analyzer_search`
Search for patterns in log files with context.

**Input:**
- `file_path` (str): Path to log file
- `pattern` (str): Regex pattern or simple text to search
- `context_lines` (int, optional): Lines before/after match (default: 3)
- `max_matches` (int, optional): Maximum matches to return (default: 50)
- `level_filter` (str, optional): Filter by log level (ERROR, WARN, etc.)
- `time_start` (str, optional): Filter from timestamp
- `time_end` (str, optional): Filter until timestamp

**Output:**
- Matching entries with context
- Line numbers
- Match count and total scanned

#### `log_analyzer_summarize`
Generate a summary of log file for debugging.

**Input:**
- `file_path` (str): Path to log file
- `focus` (str, optional): Focus area - "errors", "performance", "security", "all"
- `max_lines` (int, optional): Lines to analyze (default: 10000)

**Output:**
- Error/warning summary with counts
- Recurring patterns (grouped similar messages)
- Timeline of significant events
- Anomalies detected (spikes, gaps)
- Suggested investigation areas

#### `log_analyzer_extract_errors`
Extract all errors and exceptions with stack traces.

**Input:**
- `file_path` (str): Path to log file
- `include_warnings` (bool, optional): Include warnings (default: False)
- `group_similar` (bool, optional): Group similar errors (default: True)
- `max_errors` (int, optional): Maximum errors to return (default: 100)

**Output:**
- Grouped or individual errors
- Full stack traces where available
- First/last occurrence timestamps
- Occurrence count per error type

#### `log_analyzer_correlate`
Correlate events across time windows.

**Input:**
- `file_path` (str): Path to log file
- `anchor_pattern` (str): Pattern to anchor correlation (e.g., error message)
- `window_seconds` (int, optional): Time window around anchor (default: 60)
- `max_anchors` (int, optional): Maximum anchor points (default: 10)

**Output:**
- Events grouped by anchor occurrence
- Timeline of related events
- Potential causation chains

#### `log_analyzer_tail`
Get the most recent entries from a log file (like `tail`).

**Input:**
- `file_path` (str): Path to log file
- `lines` (int, optional): Number of lines (default: 100)
- `level_filter` (str, optional): Filter by log level

**Output:**
- Last N log entries
- Parsed and formatted

#### `log_analyzer_diff`
Compare two log files or time periods.

**Input:**
- `file_path_a` (str): First log file or "same" for time comparison
- `file_path_b` (str, optional): Second log file
- `time_range_a` (tuple, optional): Time range for first period
- `time_range_b` (tuple, optional): Time range for second period

**Output:**
- New error types in B not in A
- Volume differences
- Pattern changes

### 3. Non-Functional Requirements

#### Performance
- Handle files up to 1GB efficiently using streaming
- Never load entire file into memory
- Support for gzipped log files (.gz)
- Configurable limits to prevent context overflow

#### Output Quality
- Provide both JSON and Markdown output formats
- Keep responses concise for AI context limits
- Prioritize actionable insights over raw data
- Include line numbers for easy reference

#### Robustness
- Graceful handling of malformed lines
- Charset detection (UTF-8, Latin-1, etc.)
- Clear error messages with suggestions

## Technical Design

### Architecture

```
log_analyzer_mcp/
├── __init__.py
├── server.py           # FastMCP server entry point
├── parsers/
│   ├── __init__.py
│   ├── base.py         # Base parser class
│   ├── syslog.py
│   ├── apache.py
│   ├── jsonl.py
│   ├── python.py
│   ├── java.py
│   └── generic.py
├── analyzers/
│   ├── __init__.py
│   ├── error_extractor.py
│   ├── pattern_matcher.py
│   ├── summarizer.py
│   └── correlator.py
├── utils/
│   ├── __init__.py
│   ├── file_handler.py   # Streaming file handling
│   ├── formatters.py     # Output formatting
│   └── time_utils.py     # Timestamp parsing
└── models.py             # Pydantic models
```

### Dependencies

- `mcp` - MCP Python SDK with FastMCP
- `pydantic` - Input validation
- `python-dateutil` - Timestamp parsing
- `chardet` - Character encoding detection
- `regex` - Advanced regex support (optional)

### Format Detection Strategy

1. Read first 100 lines
2. Try each parser's `can_parse()` method
3. Score based on successful parse percentage
4. Select highest scoring parser
5. Allow format override via parameter

### Memory Management

- Use generators for line iteration
- Process in chunks of configurable size
- Aggregate results incrementally
- Discard raw data after extraction

## Test Cases

### Unit Tests
- Each parser with valid/invalid input
- Timestamp parsing edge cases
- Pattern matching accuracy
- Memory limits respected

### Integration Tests
- Real log files from various sources
- Large file handling (100MB+)
- Compressed file support
- Mixed format detection

### Example Test Logs to Generate
1. Python application with exceptions
2. Nginx access + error combined
3. Docker container logs
4. Kubernetes pod logs
5. Mixed/malformed log file

## Success Criteria

1. Correctly identifies format for 90%+ of common log files
2. Processes 100MB file in under 10 seconds
3. Provides actionable debugging insights
4. Works seamlessly with Claude Code workflow
5. Clear documentation and examples

## Future Enhancements

- Live log tailing (streaming updates)
- Multi-file correlation
- Custom parser plugin system
- Log anonymization for sharing
- Integration with observability platforms
