# Phase 3: Analyzers

## Objective
Implement analysis modules that process parsed log entries to extract insights.

## Analyzer Implementations

### 3.1 Error Extractor
**File:** `log_analyzer_mcp/analyzers/error_extractor.py`

**Purpose:** Extract all errors and exceptions with their stack traces.

**Features:**
- Identify error-level log entries
- Group multi-line stack traces with their parent entry
- Detect exception types and messages
- Count occurrences of each unique error

**Grouping Logic:**
```python
def normalize_error_message(message: str) -> str:
    """
    Normalize error messages for grouping.
    Replace variable parts with placeholders:
    - UUIDs → <UUID>
    - Numbers → <N>
    - File paths → <PATH>
    - Timestamps → <TIME>
    - IP addresses → <IP>
    """
    pass

@dataclass
class ErrorGroup:
    template: str  # Normalized message
    count: int
    first_seen: datetime
    last_seen: datetime
    sample_entries: list[ParsedLogEntry]  # First 3 occurrences
    stack_trace: Optional[str]  # If available
```

**Output Structure:**
```python
@dataclass
class ErrorExtractionResult:
    total_errors: int
    total_warnings: int
    unique_errors: int
    error_groups: list[ErrorGroup]
    time_range: tuple[datetime, datetime]
```

### 3.2 Pattern Matcher
**File:** `log_analyzer_mcp/analyzers/pattern_matcher.py`

**Purpose:** Search for patterns with context.

**Features:**
- Regex and plain text search
- Case-sensitive/insensitive options
- Context lines (before/after)
- Optional time range filtering
- Optional level filtering

**Search Result:**
```python
@dataclass
class SearchMatch:
    line_number: int
    entry: ParsedLogEntry
    context_before: list[str]  # Raw lines before match
    context_after: list[str]   # Raw lines after match
    highlight_ranges: list[tuple[int, int]]  # Character positions of matches

@dataclass
class SearchResult:
    query: str
    total_matches: int
    total_lines_scanned: int
    matches: list[SearchMatch]
    truncated: bool  # True if max_matches reached
```

### 3.3 Summarizer
**File:** `log_analyzer_mcp/analyzers/summarizer.py`

**Purpose:** Generate a debugging summary of the log file.

**Analysis Categories:**

1. **Error Summary:**
   - Top 10 most frequent errors
   - Error rate over time (spikes detection)
   - New errors (first occurrence in file)

2. **Performance Indicators:**
   - Response time patterns (if web logs)
   - Slow requests (>1s, >5s, >10s)
   - Throughput over time

3. **Security Indicators:**
   - Failed authentication attempts
   - Unusual client IPs
   - 4xx/5xx patterns by path

4. **Anomaly Detection:**
   - Log volume spikes
   - Gaps in logging (missing time periods)
   - Unusual log level distribution

**Summary Structure:**
```python
@dataclass
class LogSummary:
    file_info: FileInfo
    time_range: TimeRange
    level_distribution: dict[str, int]
    top_errors: list[ErrorGroup]
    anomalies: list[Anomaly]
    recommendations: list[str]  # Suggested investigation areas
```

### 3.4 Correlator
**File:** `log_analyzer_mcp/analyzers/correlator.py`

**Purpose:** Correlate events around specific anchor points.

**Use Case:** "What happened in the 60 seconds before this error?"

**Algorithm:**
1. Find all occurrences of anchor pattern
2. For each occurrence, collect events in time window
3. Group and analyze related events
4. Identify potential causation chains

**Correlation Result:**
```python
@dataclass
class CorrelationWindow:
    anchor_entry: ParsedLogEntry
    events_before: list[ParsedLogEntry]  # Sorted by time
    events_after: list[ParsedLogEntry]
    related_errors: list[ParsedLogEntry]
    unique_sources: list[str]  # Hostnames, processes, etc.

@dataclass
class CorrelationResult:
    anchor_pattern: str
    total_anchors: int
    windows: list[CorrelationWindow]
    common_precursors: list[str]  # Events that often appear before anchors
```

## Shared Utilities

### Memory-Efficient Processing
All analyzers must process logs in streaming fashion:

```python
class StreamingAnalyzer:
    """Base class for memory-efficient log analysis."""
    
    def process_entry(self, entry: ParsedLogEntry) -> None:
        """Process single entry - override in subclass."""
        pass
    
    def finalize(self) -> Any:
        """Called after all entries processed - return results."""
        pass
    
    def analyze_file(self, parser: BaseLogParser, file_path: str) -> Any:
        """Stream through file and return results."""
        for entry in parser.parse_file(file_path):
            self.process_entry(entry)
        return self.finalize()
```

### Output Limits
All analyzers must respect context limits:

```python
MAX_MATCHES = 100  # Maximum search results
MAX_ERRORS = 50    # Maximum error groups
MAX_SAMPLE_ENTRIES = 3  # Samples per error group
MAX_CONTEXT_LINES = 5   # Lines before/after match
MAX_STACK_TRACE_LINES = 30  # Truncate long traces
```

## Success Criteria
- [ ] Error extractor correctly groups similar errors
- [ ] Pattern matcher supports regex and plain text
- [ ] Summarizer identifies anomalies in test logs
- [ ] Correlator finds events in time windows
- [ ] All analyzers work in streaming mode
- [ ] Memory usage stays constant regardless of file size
- [ ] Unit tests with various log scenarios
- [ ] Zero type errors from mypy

## Test Commands
```bash
uv run pytest tests/test_analyzers/ -v --cov=log_analyzer_mcp/analyzers
```
