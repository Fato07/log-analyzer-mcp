# Log Analyzer MCP

[![PyPI version](https://badge.fury.io/py/codesdevs-log-analyzer.svg)](https://badge.fury.io/py/codesdevs-log-analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

An MCP (Model Context Protocol) server for AI-powered log analysis. Parse, search, and debug log files directly in Claude Code or any MCP-compatible client.

## Features

- **Auto-Detection** — Identifies log format from 9+ common formats
- **Smart Search** — Pattern matching with context lines, regex support, and time filtering
- **Error Extraction** — Groups similar errors, captures stack traces, counts occurrences
- **Summarization** — Generates debugging insights with anomaly detection
- **Correlation** — Finds related events around error occurrences
- **Real-time Watching** — Monitor logs for new entries with position tracking
- **Pattern Suggestions** — AI-powered pattern discovery for debugging
- **Streaming** — Handles large files (1GB+) without loading into memory
- **Multiple Formats** — Markdown and JSON output

## Supported Log Formats

| Format | Example Pattern |
|--------|-----------------|
| Syslog | `Jan 15 10:30:00 hostname process[pid]: message` |
| Apache/Nginx Access | `127.0.0.1 - - [15/Jan/2026:10:30:00 +0000] "GET /path" 200` |
| Apache/Nginx Error | `[Thu Jan 15 10:30:00 2026] [error] [pid 1234] message` |
| JSON Lines | `{"timestamp": "...", "level": "ERROR", "message": "..."}` |
| Docker/Container | `2026-01-15T10:30:00.123Z stdout message` |
| Python Logging | `2026-01-15 10:30:00,123 - module - ERROR - message` |
| Java/Log4j | `2026-01-15 10:30:00,123 ERROR [thread] class - message` |
| Kubernetes | `level=error msg="..." ts=2026-01-15T10:30:00Z` |
| Generic Timestamp | Any line with recognizable timestamp |

## Installation

### Quick Install (Recommended)

```bash
uvx codesdevs-log-analyzer install
```

This automatically adds the MCP server to your Claude Code settings. Restart Claude Code to start using it.

To uninstall:
```bash
uvx codesdevs-log-analyzer uninstall
```

### Manual Installation

#### pip
```bash
pip install codesdevs-log-analyzer
```

#### uv
```bash
uv tool install codesdevs-log-analyzer
```

#### Claude Code

Add to your `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "log-analyzer": {
      "command": "uvx",
      "args": ["codesdevs-log-analyzer"]
    }
  }
}
```

Or if installed via pip:
```json
{
  "mcpServers": {
    "log-analyzer": {
      "command": "codesdevs-log-analyzer"
    }
  }
}
```

Restart Claude Code and the tools will be available.

## Usage

### With Claude Code

Just describe what you need:

```
Analyze /var/log/nginx/error.log and tell me what's causing the 502 errors
```

```
Search for "timeout" in my app.log with 5 lines of context before and after
```

```
Give me a summary of errors from /var/log/app.log in the last hour
```

```
What happened in the 60 seconds before each OutOfMemoryError in my Java logs?
```

### Available Tools

| Tool | Description |
|------|-------------|
| `log_analyzer_parse` | Detect format, extract metadata, show samples |
| `log_analyzer_search` | Search patterns with context |
| `log_analyzer_extract_errors` | Extract and group all errors |
| `log_analyzer_summarize` | Generate debugging summary |
| `log_analyzer_tail` | Get recent log entries |
| `log_analyzer_correlate` | Find events around anchor patterns |
| `log_analyzer_diff` | Compare log files or time periods |
| `log_analyzer_watch` | Watch log file for new entries (polling-based) |
| `log_analyzer_suggest_patterns` | Suggest useful search patterns based on log content |

## Examples

### Analyze a Log File

**Prompt:**
```
Analyze /var/log/app.log
```

**Output:**
```markdown
## Log Analysis: /var/log/app.log

**Format:** Python logging (confidence: 98%)
**Lines:** 15,432 parsed
**Time Range:** 2026-01-15 00:00:01 → 23:59:58

### Level Distribution
ERROR  ████████░░░░░░░░░░░░  1,234 (8%)
WARN   ██████████░░░░░░░░░░  2,345 (15%)
INFO   ████████████████████  11,853 (77%)

### Sample Entries
[First 5 and last 5 entries shown]
```

### Search with Context

**Prompt:**
```
Search for "connection refused" in /var/log/nginx/error.log with 3 lines context
```

**Output:**
```markdown
## Search Results: "connection refused"

Found **23 matches** in 5,432 lines

### Match 1 (line 1234)
```
[context before]
2026-01-15 10:30:00 [error] connect() failed: Connection refused
[context after]
```
...
```

### Extract Errors with Stack Traces

**Prompt:**
```
Extract all errors from /var/log/java-app.log, group similar ones
```

**Output:**
```markdown
## Errors: /var/log/java-app.log

**Total:** 456 errors (23 unique patterns)

### 1. NullPointerException (187 occurrences)
- **First:** 2026-01-15 03:45:12
- **Last:** 2026-01-15 22:15:33
- **Sample:**
  ```
  java.lang.NullPointerException: Cannot invoke method on null
      at com.example.UserService.getUser(UserService.java:45)
      at com.example.ApiController.handleRequest(ApiController.java:123)
  ```
...
```

### Watch Logs for New Errors

**Prompt:**
```
Watch /var/log/app.log for new errors while I test my changes
```

**Usage:**
```
# First call - get current position
log_analyzer_watch(file_path="/var/log/app.log", from_position=0)
# Returns: current_position=123456

# After triggering action - check for new errors
log_analyzer_watch(file_path="/var/log/app.log", from_position=123456, level_filter="ERROR")
# Returns: new_entries=[...], current_position=234567
```

### Get Pattern Suggestions

**Prompt:**
```
What patterns should I search for in /var/log/app.log to debug this issue?
```

**Output:**
```markdown
## Suggested Patterns for /var/log/app.log

### High Priority

1. **Database Connection Errors** (23 matches)
   - Pattern: `connection (refused|timeout|reset)`
   - Example: "connection refused to postgres:5432"

2. **Authentication Failures** (15 matches)
   - Pattern: `(auth|login|authentication) failed`
   - Example: "authentication failed for user admin"

### Medium Priority

3. **Request IDs** (1,234 matches)
   - Pattern: `req-[a-f0-9]{8}`
   - Use for tracing specific requests
```

## Tool Parameters

### log_analyzer_parse

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `format_hint` | string | auto | Force specific format |
| `max_lines` | int | 10000 | Lines to analyze |
| `response_format` | string | markdown | `markdown` or `json` |

### log_analyzer_search

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `pattern` | string | required | Search pattern |
| `is_regex` | bool | false | Use regex matching |
| `context_lines` | int | 3 | Lines before/after |
| `max_matches` | int | 50 | Maximum results |
| `level_filter` | string | null | Filter by level |
| `time_start` | string | null | Filter from time |
| `time_end` | string | null | Filter until time |

### log_analyzer_extract_errors

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `include_warnings` | bool | false | Include WARN level |
| `group_similar` | bool | true | Group similar errors |
| `max_errors` | int | 100 | Maximum errors |

### log_analyzer_summarize

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `focus` | string | all | `errors`, `performance`, `security`, `all` |
| `max_lines` | int | 10000 | Lines to analyze |

### log_analyzer_correlate

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `anchor_pattern` | string | required | Pattern to correlate around |
| `window_seconds` | int | 60 | Time window |
| `max_anchors` | int | 10 | Maximum anchor points |

### log_analyzer_watch

Watch a log file for new entries using position-based polling. Useful for real-time monitoring.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `from_position` | int | 0 | File position to start from (0 = get current end) |
| `max_lines` | int | 100 | Maximum lines to read per call |
| `level_filter` | string | null | Filter by level (e.g., `ERROR` or `ERROR,WARN`) |
| `pattern_filter` | string | null | Regex pattern to filter messages |

**Usage Flow:**
1. First call with `from_position=0` returns current file position
2. Subsequent calls with returned position get new entries
3. Repeat to "watch" for new log entries

### log_analyzer_suggest_patterns

Analyze a log file and suggest useful search patterns based on content analysis.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `focus` | string | all | Focus area: `all`, `errors`, `security`, `performance`, `identifiers` |
| `max_patterns` | int | 10 | Maximum patterns to suggest |
| `max_lines` | int | 10000 | Lines to analyze |

**Focus Areas:**
- `all` — Analyze all pattern categories
- `errors` — Focus on error message patterns
- `security` — Focus on auth failures, unauthorized access
- `performance` — Focus on slow requests, timeouts
- `identifiers` — Focus on UUIDs, request IDs, user IDs

## Development

### Setup
```bash
git clone https://github.com/Fato07/log-analyzer-mcp
cd log-analyzer-mcp
uv sync
```

### Run Tests
```bash
uv run pytest -v --cov
```

### Type Checking
```bash
uv run mypy codesdevs_log_analyzer
```

### Run Locally
```bash
uv run codesdevs-log-analyzer
```

### Test with MCP Inspector
```bash
npx @modelcontextprotocol/inspector uv run codesdevs-log-analyzer
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Links

- [Report bugs](https://github.com/Fato07/log-analyzer-mcp/issues)
- [Request features](https://github.com/Fato07/log-analyzer-mcp/issues)
- [Discussions](https://github.com/Fato07/log-analyzer-mcp/discussions)

---

Built by [Fato07](https://github.com/Fato07) at [CodesDevs](https://codesdevs.io)
