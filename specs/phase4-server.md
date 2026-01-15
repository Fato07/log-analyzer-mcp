# Phase 4: MCP Server & Tools

## Objective
Implement the FastMCP server with all 7 tools, following MCP best practices.

## Server Setup
**File:** `log_analyzer_mcp/server.py`

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("log_analyzer_mcp")

def main():
    """Entry point for the MCP server."""
    mcp.run()

if __name__ == "__main__":
    main()
```

## Tool Implementations

### 4.1 log_analyzer_parse (P0)
**Purpose:** Parse and detect log format, extract metadata.

**Input Model:**
```python
class ParseInput(BaseModel):
    file_path: str = Field(..., description="Path to the log file to analyze")
    format_hint: Optional[str] = Field(
        default=None, 
        description="Force specific format: syslog, apache_access, apache_error, jsonl, docker, python, java, kubernetes, generic"
    )
    max_lines: int = Field(
        default=10000, 
        ge=100, 
        le=100000,
        description="Maximum lines to parse for analysis"
    )
    response_format: ResponseFormat = Field(
        default=ResponseFormat.MARKDOWN,
        description="Output format: markdown or json"
    )
```

**Output:**
- Detected format (with confidence)
- Total lines / parsed lines
- Time range (first/last timestamp)
- Log level distribution
- Sample entries (first 5, last 5)
- File size and encoding

**Annotations:**
- `readOnlyHint`: True
- `destructiveHint`: False
- `idempotentHint`: True
- `openWorldHint`: False

### 4.2 log_analyzer_search (P0)
**Purpose:** Search for patterns with context.

**Input Model:**
```python
class SearchInput(BaseModel):
    file_path: str = Field(..., description="Path to the log file")
    pattern: str = Field(..., description="Search pattern (regex or plain text)", min_length=1)
    is_regex: bool = Field(default=False, description="Treat pattern as regex")
    case_sensitive: bool = Field(default=False, description="Case-sensitive search")
    context_lines: int = Field(default=3, ge=0, le=10, description="Lines of context before/after match")
    max_matches: int = Field(default=50, ge=1, le=200, description="Maximum matches to return")
    level_filter: Optional[str] = Field(default=None, description="Filter by log level: ERROR, WARN, INFO, DEBUG")
    time_start: Optional[str] = Field(default=None, description="Filter from timestamp (ISO format)")
    time_end: Optional[str] = Field(default=None, description="Filter until timestamp (ISO format)")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)
```

**Output:**
- Match count (shown/total)
- Each match with:
  - Line number
  - Timestamp (if available)
  - Level (if available)
  - Context before/after
  - Highlighted match

### 4.3 log_analyzer_extract_errors (P0)
**Purpose:** Extract all errors and exceptions with stack traces.

**Input Model:**
```python
class ExtractErrorsInput(BaseModel):
    file_path: str = Field(..., description="Path to the log file")
    include_warnings: bool = Field(default=False, description="Include WARN level entries")
    group_similar: bool = Field(default=True, description="Group similar error messages")
    max_errors: int = Field(default=100, ge=1, le=500, description="Maximum errors to return")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)
```

**Output:**
- Error count (total, unique)
- Warning count (if included)
- Grouped errors with:
  - Normalized message template
  - Occurrence count
  - First/last seen timestamps
  - Sample entries with stack traces
  - Line numbers

### 4.4 log_analyzer_summarize (P1)
**Purpose:** Generate debugging summary.

**Input Model:**
```python
class SummarizeInput(BaseModel):
    file_path: str = Field(..., description="Path to the log file")
    focus: str = Field(
        default="all",
        description="Focus area: errors, performance, security, all"
    )
    max_lines: int = Field(default=10000, ge=100, le=100000, description="Lines to analyze")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)
```

**Output:**
- File overview (size, time range, format)
- Level distribution chart (ASCII)
- Top errors (by frequency)
- Anomalies detected
- Recommended investigation areas

### 4.5 log_analyzer_tail (P1)
**Purpose:** Get recent log entries.

**Input Model:**
```python
class TailInput(BaseModel):
    file_path: str = Field(..., description="Path to the log file")
    lines: int = Field(default=100, ge=1, le=1000, description="Number of lines to return")
    level_filter: Optional[str] = Field(default=None, description="Filter by log level")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)
```

**Output:**
- Last N log entries
- Parsed and formatted
- Line numbers included

### 4.6 log_analyzer_correlate (P2)
**Purpose:** Correlate events around anchor points.

**Input Model:**
```python
class CorrelateInput(BaseModel):
    file_path: str = Field(..., description="Path to the log file")
    anchor_pattern: str = Field(..., description="Pattern to anchor correlation around")
    window_seconds: int = Field(default=60, ge=1, le=3600, description="Time window in seconds")
    max_anchors: int = Field(default=10, ge=1, le=50, description="Maximum anchor points to analyze")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)
```

**Output:**
- Anchor occurrences found
- For each anchor:
  - Events before (in window)
  - Events after (in window)
  - Related errors
- Common precursor patterns

### 4.7 log_analyzer_diff (P2)
**Purpose:** Compare log files or time periods.

**Input Model:**
```python
class DiffInput(BaseModel):
    file_path_a: str = Field(..., description="First log file path")
    file_path_b: Optional[str] = Field(default=None, description="Second log file (omit for time comparison)")
    time_range_a: Optional[tuple[str, str]] = Field(default=None, description="Time range for first period")
    time_range_b: Optional[tuple[str, str]] = Field(default=None, description="Time range for second period")
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)
```

**Output:**
- New error types in B (not in A)
- Error volume comparison
- Pattern changes
- Timeline comparison

## Error Handling

All tools must handle errors gracefully:

```python
def handle_tool_error(error: Exception, file_path: str) -> str:
    """Generate helpful error message."""
    if isinstance(error, FileNotFoundError):
        return f"Error: File not found: {file_path}\nPlease check the path and try again."
    if isinstance(error, PermissionError):
        return f"Error: Permission denied: {file_path}\nCheck file permissions."
    if isinstance(error, UnicodeDecodeError):
        return f"Error: Unable to decode file. Try specifying encoding or check if file is binary."
    return f"Error: {type(error).__name__}: {str(error)}"
```

## Output Formatting

### Markdown Format (Default)
```markdown
## Log Analysis Results

**File:** `/var/log/app.log`
**Format:** Python logging (confidence: 98%)
**Lines:** 15,432 parsed

### Time Range
- **Start:** 2026-01-15 00:00:01
- **End:** 2026-01-15 23:59:58

### Level Distribution
```
ERROR  ████████░░░░░░░░░░░░  1,234 (8%)
WARN   ██████████░░░░░░░░░░  2,345 (15%)
INFO   ████████████████████  11,853 (77%)
```

### Top Errors
1. **ConnectionTimeout** (423 occurrences)
   - First: 2026-01-15 03:45:12
   - Last: 2026-01-15 22:15:33
   - Sample: `Connection to db.example.com:5432 timed out after 30s`
...
```

### JSON Format
```json
{
  "file": "/var/log/app.log",
  "format": {"name": "python", "confidence": 0.98},
  "lines": {"total": 15432, "parsed": 15432},
  "time_range": {
    "start": "2026-01-15T00:00:01Z",
    "end": "2026-01-15T23:59:58Z"
  },
  "levels": {
    "ERROR": 1234,
    "WARN": 2345,
    "INFO": 11853
  }
}
```

## Integration Tests

**File:** `tests/test_server.py`

Test each tool end-to-end:
1. Create test log file
2. Call tool via MCP interface
3. Verify response structure
4. Verify response content

```python
@pytest.mark.asyncio
async def test_parse_tool():
    """Test log_analyzer_parse tool."""
    # Create test log
    test_log = create_python_log_file(100)
    
    # Call tool
    result = await mcp.call_tool("log_analyzer_parse", {
        "file_path": test_log,
        "response_format": "json"
    })
    
    # Verify
    data = json.loads(result)
    assert data["format"]["name"] == "python"
    assert data["lines"]["total"] == 100
```

## Success Criteria
- [ ] All 7 tools implemented with proper annotations
- [ ] All input models have Field() with descriptions
- [ ] All tools support markdown and json output
- [ ] Error messages are helpful and actionable
- [ ] Tools handle edge cases gracefully
- [ ] Integration tests pass for all tools
- [ ] Server runs without errors: `uv run log-analyzer-mcp`
- [ ] MCP Inspector shows all tools correctly

## Test Commands
```bash
# Unit tests
uv run pytest tests/test_server.py -v

# Run server
uv run log-analyzer-mcp

# Test with inspector
npx @modelcontextprotocol/inspector uv run log-analyzer-mcp
```
