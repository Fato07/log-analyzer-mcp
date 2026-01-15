# Phase 1: Core Infrastructure

## Objective
Set up project foundation with base classes, utilities, and Pydantic models.

## Tasks

### 1.1 Create Base Parser Interface
**File:** `log_analyzer_mcp/parsers/base.py`

Create abstract base class for all log parsers:
```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Iterator, Any

@dataclass
class ParsedLogEntry:
    line_number: int
    raw_line: str
    timestamp: Optional[datetime]
    level: Optional[str]  # ERROR, WARN, INFO, DEBUG, etc.
    message: str
    metadata: dict[str, Any]  # Parser-specific fields

class BaseLogParser(ABC):
    name: str
    patterns: list[str]  # Regex patterns this parser handles
    
    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Check if this parser can handle the line."""
        pass
    
    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        """Parse a single log line."""
        pass
    
    def parse_file(self, file_path: str, max_lines: int = 10000) -> Iterator[ParsedLogEntry]:
        """Stream parse a file."""
        pass
    
    @classmethod
    def detect_confidence(cls, sample_lines: list[str]) -> float:
        """Return 0.0-1.0 confidence score for format detection."""
        pass
```

### 1.2 Create Pydantic Models
**File:** `log_analyzer_mcp/models.py`

Define all input/output models:
- `LogFormat` enum
- `ResponseFormat` enum (markdown, json)
- `LogLevel` enum
- Input models for each tool
- Output models for structured responses

### 1.3 Create File Handler Utilities
**File:** `log_analyzer_mcp/utils/file_handler.py`

- `stream_file()` - Generator that yields lines without loading entire file
- `read_tail()` - Read last N lines efficiently (seek from end)
- `detect_encoding()` - Use chardet to detect file encoding
- `handle_gzip()` - Transparent gzip support

### 1.4 Create Time Utilities
**File:** `log_analyzer_mcp/utils/time_utils.py`

- `parse_timestamp()` - Parse various timestamp formats to datetime
- `format_timestamp()` - Convert datetime to human-readable string
- `parse_relative_time()` - Handle "1h ago", "yesterday", etc.
- Common timestamp patterns as constants

### 1.5 Create Output Formatters
**File:** `log_analyzer_mcp/utils/formatters.py`

- `format_as_markdown()` - Format results for human readability
- `format_as_json()` - Format results for programmatic use
- `truncate_for_context()` - Ensure output fits in AI context limits

## Success Criteria
- [ ] `BaseLogParser` class with all abstract methods
- [ ] All Pydantic models with Field() descriptions
- [ ] File streaming works with 100MB+ files
- [ ] Timestamp parsing handles 10+ common formats
- [ ] Unit tests for all utilities
- [ ] Zero type errors from mypy

## Test Commands
```bash
uv run pytest tests/test_utils.py -v
uv run mypy log_analyzer_mcp/utils log_analyzer_mcp/models.py log_analyzer_mcp/parsers/base.py
```
