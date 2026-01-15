# Phase 2: Log Parsers

## Objective
Implement all 9 log format parsers with auto-detection capability.

## Parser Implementations

### 2.1 Syslog Parser
**File:** `log_analyzer_mcp/parsers/syslog.py`

**Format:** `Jan 15 10:30:00 hostname process[pid]: message`

**Regex Pattern:**
```regex
^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$
```

**Extracted Fields:**
- timestamp (Month Day HH:MM:SS)
- hostname
- process_name
- pid (optional)
- message

**Priority Detection:** Look for months (Jan, Feb, etc.) at line start.

### 2.2 Apache/Nginx Access Log Parser
**File:** `log_analyzer_mcp/parsers/apache.py`

**Combined Log Format:**
```
127.0.0.1 - - [15/Jan/2026:10:30:00 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"
```

**Extracted Fields:**
- client_ip
- timestamp
- method
- path
- protocol
- status_code
- bytes_sent
- referer
- user_agent

**Level Mapping:**
- 5xx → ERROR
- 4xx → WARN
- 3xx → INFO
- 2xx → DEBUG

### 2.3 Apache/Nginx Error Log Parser
**File:** `log_analyzer_mcp/parsers/apache.py` (same file, different class)

**Format:**
```
[Thu Jan 15 10:30:00.123456 2026] [error] [pid 1234] [client 127.0.0.1:8080] message
```

**Extracted Fields:**
- timestamp
- level (error, warn, notice, etc.)
- pid
- client_ip (optional)
- message

### 2.4 JSON Lines Parser
**File:** `log_analyzer_mcp/parsers/jsonl.py`

**Format:** One JSON object per line

**Common Field Mappings:**
```python
TIMESTAMP_FIELDS = ['timestamp', 'time', 'ts', '@timestamp', 'datetime', 'date']
LEVEL_FIELDS = ['level', 'severity', 'log_level', 'loglevel', 'lvl']
MESSAGE_FIELDS = ['message', 'msg', 'text', 'log', 'body']
```

**Features:**
- Auto-detect field names
- Flatten nested objects for metadata
- Handle malformed JSON gracefully

### 2.5 Docker/Container Log Parser
**File:** `log_analyzer_mcp/parsers/docker.py`

**Format:**
```
2026-01-15T10:30:00.123456789Z stdout P message
2026-01-15T10:30:00.123456789Z stderr F error message
```

**Extracted Fields:**
- timestamp (RFC3339Nano)
- stream (stdout/stderr)
- partial_flag (P=partial, F=full)
- message

**Level Mapping:**
- stderr → ERROR
- stdout → INFO

### 2.6 Python Logging Parser
**File:** `log_analyzer_mcp/parsers/python_log.py`

**Default Format:**
```
2026-01-15 10:30:00,123 - module.name - ERROR - Message text
```

**Alternative Formats:**
```
ERROR:module.name:Message text
[2026-01-15 10:30:00] ERROR module: Message
```

**Extracted Fields:**
- timestamp
- module/logger name
- level
- message

**Stack Trace Detection:**
- Lines starting with "Traceback"
- Indented lines with "File" and line numbers
- Exception type and message

### 2.7 Java/Log4j Parser
**File:** `log_analyzer_mcp/parsers/java.py`

**Common Format:**
```
2026-01-15 10:30:00,123 ERROR [main] com.example.Class - Message
```

**Alternative:**
```
2026-01-15 10:30:00.123 [main] ERROR c.e.Class - Message
```

**Extracted Fields:**
- timestamp
- level
- thread name
- logger/class name
- message

**Stack Trace Detection:**
- Lines starting with "at "
- "Caused by:" patterns
- Exception type with message

### 2.8 Kubernetes Log Parser
**File:** `log_analyzer_mcp/parsers/kubernetes.py`

**Format (kubectl logs):**
```
2026-01-15T10:30:00.123456Z level=error msg="Error message" key=value
```

**Also handles structured k8s JSON:**
```json
{"ts":"2026-01-15T10:30:00.123Z","level":"error","msg":"Error","pod":"name"}
```

**Extracted Fields:**
- timestamp
- level
- message
- key-value pairs as metadata

### 2.9 Generic Timestamp Parser
**File:** `log_analyzer_mcp/parsers/generic.py`

**Purpose:** Fallback for any log with recognizable timestamps.

**Timestamp Patterns to Detect:**
- ISO 8601: `2026-01-15T10:30:00Z`
- ISO with space: `2026-01-15 10:30:00`
- US format: `01/15/2026 10:30:00`
- European: `15/01/2026 10:30:00`
- Unix epoch: `1736934600`
- Milliseconds: `1736934600000`

**Level Detection:**
- Scan line for ERROR, WARN, INFO, DEBUG keywords
- Case-insensitive matching

## Parser Registry
**File:** `log_analyzer_mcp/parsers/__init__.py`

```python
def detect_format(file_path: str, sample_size: int = 100) -> tuple[BaseLogParser, float]:
    """
    Read first sample_size lines and return best parser with confidence score.
    
    Returns:
        Tuple of (parser_instance, confidence_score)
    """
    pass

def get_parser(format_name: str) -> BaseLogParser:
    """Get parser by name."""
    pass

PARSER_REGISTRY: dict[str, type[BaseLogParser]] = {
    'syslog': SyslogParser,
    'apache_access': ApacheAccessParser,
    'apache_error': ApacheErrorParser,
    'jsonl': JSONLParser,
    'docker': DockerParser,
    'python': PythonLogParser,
    'java': JavaLogParser,
    'kubernetes': KubernetesParser,
    'generic': GenericParser,
}
```

## Test Log Files to Generate
**Directory:** `test_logs/`

Create realistic test files for each format with:
- Normal entries
- Edge cases (missing fields, unusual timestamps)
- Errors with stack traces
- Multi-line messages
- Unicode content

## Success Criteria
- [ ] All 9 parsers implemented
- [ ] Each parser has `can_parse()` with >90% accuracy
- [ ] Auto-detection correctly identifies format in >90% of cases
- [ ] Stack traces properly grouped with parent log entry
- [ ] Malformed lines don't crash parsers
- [ ] Unit tests for each parser with edge cases
- [ ] Zero type errors from mypy

## Test Commands
```bash
uv run pytest tests/test_parsers/ -v --cov=log_analyzer_mcp/parsers
```
