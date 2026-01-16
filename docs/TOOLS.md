# Tool Reference

Complete reference for all 14 log-analyzer-mcp tools.

## Quick Reference

| Tool | Purpose |
|------|---------|
| `log_analyzer_parse` | Detect format, extract metadata, show samples |
| `log_analyzer_search` | Search patterns with context |
| `log_analyzer_extract_errors` | Extract and group all errors |
| `log_analyzer_summarize` | Generate debugging summary |
| `log_analyzer_tail` | Get recent log entries |
| `log_analyzer_correlate` | Find events around anchor patterns |
| `log_analyzer_diff` | Compare log files or time periods |
| `log_analyzer_watch` | Watch log file for new entries |
| `log_analyzer_suggest_patterns` | Suggest useful search patterns |
| `log_analyzer_trace` | Extract and follow trace IDs |
| `log_analyzer_multi` | Analyze logs across multiple files |
| `log_analyzer_ask` | Natural language queries |
| `log_analyzer_scan_sensitive` | Detect PII, credentials, secrets |
| `log_analyzer_suggest_format` | Suggest log format |

---

## log_analyzer_parse

Parse and detect log format with metadata extraction.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `format_hint` | string | auto | Force specific format |
| `max_lines` | int | 10000 | Lines to analyze |
| `response_format` | string | markdown | `markdown` or `json` |

---

## log_analyzer_search

Search patterns with context lines and filtering.

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

---

## log_analyzer_extract_errors

Extract all errors with stack traces, grouped by similarity.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `include_warnings` | bool | false | Include WARN level |
| `group_similar` | bool | true | Group similar errors |
| `max_errors` | int | 100 | Maximum errors |

---

## log_analyzer_summarize

Generate debugging summary with statistics.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `focus` | string | all | `errors`, `performance`, `security`, `all` |
| `max_lines` | int | 10000 | Lines to analyze |

---

## log_analyzer_tail

Get recent log entries.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `lines` | int | 100 | Number of lines |
| `level_filter` | string | null | Filter by level |

---

## log_analyzer_correlate

Correlate events within time windows around anchor patterns.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `anchor_pattern` | string | required | Pattern to correlate around |
| `window_seconds` | int | 60 | Time window |
| `max_anchors` | int | 10 | Maximum anchor points |

---

## log_analyzer_diff

Compare log files or time periods.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to first log file |
| `file_path_2` | string | null | Path to second log file |
| `time_start` | string | null | Start time for comparison |
| `time_end` | string | null | End time for comparison |

---

## log_analyzer_watch

Watch a log file for new entries using position-based polling.

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

---

## log_analyzer_suggest_patterns

Analyze log content and suggest useful search patterns.

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

---

## log_analyzer_trace

Extract and follow trace/correlation IDs across log entries.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `trace_id` | string | null | Specific trace ID to extract (null = all traces) |
| `trace_patterns` | list | auto | Custom regex patterns for trace IDs |
| `max_traces` | int | 50 | Maximum traces to return |
| `max_lines` | int | 100000 | Lines to scan |

**Auto-detected formats:** OpenTelemetry, UUID, AWS X-Ray, custom patterns.

---

## log_analyzer_multi

Analyze and correlate logs across multiple files.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_paths` | list | required | List of log file paths |
| `operation` | string | merge | `merge`, `correlate`, or `compare` |
| `time_window_seconds` | int | 60 | Time window for correlation |
| `max_entries` | int | 1000 | Maximum entries to return |

**Operations:**
- `merge` — Interleave entries by timestamp
- `correlate` — Find events across files within time window
- `compare` — Diff error patterns between files

---

## log_analyzer_ask

Translate natural language questions into tool calls.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `question` | string | required | Natural language question about the logs |

**Example Questions:**
- "What errors happened in the last hour?"
- "Show me failed login attempts"
- "What's causing the high latency?"

---

## log_analyzer_scan_sensitive

Scan for PII, credentials, and sensitive data in logs.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `redact` | bool | false | Redact sensitive data in output |
| `categories` | list | all | Filter categories (see below) |
| `max_matches` | int | 100 | Maximum matches to return |
| `max_lines` | int | 100000 | Lines to scan |

**Categories:**
- `email` — Email addresses
- `credit_card` — Credit card numbers
- `api_key` — API keys
- `password` — Passwords in URLs/strings
- `ssn` — Social Security Numbers
- `ip_address` — IP addresses
- `phone` — Phone numbers
- `token` — JWT and bearer tokens
- `connection_string` — Database connection strings
- `private_key` — Private keys

---

## log_analyzer_suggest_format

Suggest log format based on content analysis.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file_path` | string | required | Path to log file |
| `sample_lines` | int | 100 | Lines to sample |
