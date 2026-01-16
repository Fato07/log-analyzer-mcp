"""Pydantic models for log-analyzer-mcp inputs and outputs."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class LogFormat(str, Enum):
    """Supported log formats for parsing."""

    SYSLOG = "syslog"
    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    JSONL = "jsonl"
    DOCKER = "docker"
    PYTHON = "python"
    JAVA = "java"
    KUBERNETES = "kubernetes"
    GENERIC = "generic"
    AUTO = "auto"


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


class LogLevel(str, Enum):
    """Standard log severity levels."""

    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARN = "WARN"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    FATAL = "FATAL"
    EMERGENCY = "EMERGENCY"

    @classmethod
    def normalize(cls, level: str | None) -> "LogLevel | None":
        """Normalize a log level string to a standard LogLevel enum value."""
        if level is None:
            return None

        level_upper = level.upper().strip()

        # Direct matches
        for log_level in cls:
            if level_upper == log_level.value:
                return log_level

        # Common aliases
        aliases: dict[str, LogLevel] = {
            "ERR": cls.ERROR,
            "SEVERE": cls.ERROR,
            "CRIT": cls.CRITICAL,
            "EMERG": cls.EMERGENCY,
            "DBG": cls.DEBUG,
            "INF": cls.INFO,
            "WRN": cls.WARN,
            "WARNING": cls.WARN,
        }

        return aliases.get(level_upper)


# ============================================================================
# Helper Models
# ============================================================================


class FileInfo(BaseModel):
    """Information about a log file."""

    path: str = Field(..., description="File path")
    size_bytes: int = Field(..., description="File size in bytes")
    total_lines: int = Field(..., description="Total number of lines")
    detected_format: LogFormat = Field(..., description="Detected log format")
    encoding: str = Field(default="utf-8", description="File encoding")


class TimeRange(BaseModel):
    """A time range."""

    start: datetime | None = Field(None, description="Start of time range")
    end: datetime | None = Field(None, description="End of time range")

    @property
    def duration_seconds(self) -> float | None:
        """Get duration in seconds."""
        if self.start and self.end:
            return (self.end - self.start).total_seconds()
        return None


class Anomaly(BaseModel):
    """A detected anomaly in log data."""

    type: str = Field(..., description="Type of anomaly (spike, gap, unusual_level)")
    description: str = Field(..., description="Human-readable description")
    severity: str = Field(default="medium", description="Severity: low, medium, high")
    timestamp: datetime | None = Field(None, description="When the anomaly occurred")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")


# ============================================================================
# Parsed Log Entry Model
# ============================================================================


class ParsedLogEntry(BaseModel):
    """A single parsed log entry with extracted fields."""

    line_number: int = Field(..., description="1-indexed line number in the source file")
    raw_line: str = Field(..., description="Original unparsed log line")
    timestamp: datetime | None = Field(None, description="Parsed timestamp if found")
    level: LogLevel | None = Field(None, description="Log severity level if detected")
    message: str = Field(..., description="Main log message content")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Parser-specific extracted fields"
    )

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


# ============================================================================
# Tool Input Models
# ============================================================================


class ParseInput(BaseModel):
    """Input for log_analyzer_parse tool."""

    file_path: str = Field(..., description="Path to the log file to parse")
    format: LogFormat = Field(
        LogFormat.AUTO, description="Log format to use, or 'auto' for detection"
    )
    max_lines: int = Field(1000, description="Maximum number of lines to parse", ge=1, le=100000)
    response_format: ResponseFormat = Field(
        ResponseFormat.MARKDOWN, description="Output format for the response"
    )


class SearchInput(BaseModel):
    """Input for log_analyzer_search tool."""

    file_path: str = Field(..., description="Path to the log file to search")
    pattern: str = Field(..., description="Regex pattern to search for")
    context_lines: int = Field(
        3, description="Number of context lines before and after matches", ge=0, le=20
    )
    max_results: int = Field(50, description="Maximum number of matches to return", ge=1, le=500)
    case_sensitive: bool = Field(False, description="Whether search is case-sensitive")
    format: LogFormat = Field(LogFormat.AUTO, description="Log format for parsing")
    response_format: ResponseFormat = Field(
        ResponseFormat.MARKDOWN, description="Output format for the response"
    )


class ExtractErrorsInput(BaseModel):
    """Input for log_analyzer_extract_errors tool."""

    file_path: str = Field(..., description="Path to the log file")
    include_warnings: bool = Field(False, description="Include WARN level entries")
    group_similar: bool = Field(True, description="Group similar error messages together")
    max_errors: int = Field(100, description="Maximum errors to return", ge=1, le=1000)
    format: LogFormat = Field(LogFormat.AUTO, description="Log format for parsing")
    response_format: ResponseFormat = Field(
        ResponseFormat.MARKDOWN, description="Output format for the response"
    )


class SummarizeInput(BaseModel):
    """Input for log_analyzer_summarize tool."""

    file_path: str = Field(..., description="Path to the log file")
    time_range_start: datetime | None = Field(None, description="Start of time range to analyze")
    time_range_end: datetime | None = Field(None, description="End of time range to analyze")
    format: LogFormat = Field(LogFormat.AUTO, description="Log format for parsing")
    response_format: ResponseFormat = Field(
        ResponseFormat.MARKDOWN, description="Output format for the response"
    )


class TailInput(BaseModel):
    """Input for log_analyzer_tail tool."""

    file_path: str = Field(..., description="Path to the log file")
    lines: int = Field(50, description="Number of lines to read from end", ge=1, le=1000)
    format: LogFormat = Field(LogFormat.AUTO, description="Log format for parsing")
    response_format: ResponseFormat = Field(
        ResponseFormat.MARKDOWN, description="Output format for the response"
    )


class CorrelateInput(BaseModel):
    """Input for log_analyzer_correlate tool."""

    file_paths: list[str] = Field(..., description="List of log file paths to correlate")
    time_window: int = Field(60, description="Time window in seconds for correlation", ge=1)
    format: LogFormat = Field(LogFormat.AUTO, description="Log format for parsing")
    response_format: ResponseFormat = Field(
        ResponseFormat.MARKDOWN, description="Output format for the response"
    )


class DiffInput(BaseModel):
    """Input for log_analyzer_diff tool."""

    file_path1: str = Field(..., description="First log file path")
    file_path2: str | None = Field(None, description="Second log file path (optional)")
    time_range1_start: datetime | None = Field(None, description="Start time for first range")
    time_range1_end: datetime | None = Field(None, description="End time for first range")
    time_range2_start: datetime | None = Field(None, description="Start time for second range")
    time_range2_end: datetime | None = Field(None, description="End time for second range")
    format: LogFormat = Field(LogFormat.AUTO, description="Log format for parsing")
    response_format: ResponseFormat = Field(
        ResponseFormat.MARKDOWN, description="Output format for the response"
    )


# ============================================================================
# Tool Output Models
# ============================================================================


class FormatDetectionResult(BaseModel):
    """Result of log format detection."""

    detected_format: LogFormat = Field(..., description="Detected log format")
    confidence: float = Field(..., description="Confidence score 0.0-1.0", ge=0.0, le=1.0)
    sample_parsed: int = Field(..., description="Number of lines successfully parsed")
    sample_total: int = Field(..., description="Total lines sampled")


class ParseResult(BaseModel):
    """Result of parsing log file."""

    file_path: str = Field(..., description="Path to parsed file")
    format_detection: FormatDetectionResult = Field(..., description="Format detection result")
    total_lines: int = Field(..., description="Total lines processed")
    parsed_lines: int = Field(..., description="Lines successfully parsed")
    entries: list[ParsedLogEntry] = Field(..., description="Parsed log entries")
    time_range_start: datetime | None = Field(None, description="Earliest timestamp found")
    time_range_end: datetime | None = Field(None, description="Latest timestamp found")
    level_counts: dict[str, int] = Field(
        default_factory=dict, description="Count of entries by log level"
    )


class SearchMatch(BaseModel):
    """A single search match with context."""

    entry: ParsedLogEntry = Field(..., description="The matching log entry")
    context_before: list[str] = Field(..., description="Lines before the match")
    context_after: list[str] = Field(..., description="Lines after the match")
    match_highlights: list[tuple[int, int]] = Field(
        ..., description="Start/end positions of matches in message"
    )


class SearchResult(BaseModel):
    """Result of log search."""

    file_path: str = Field(..., description="Path to searched file")
    pattern: str = Field(..., description="Search pattern used")
    total_matches: int = Field(..., description="Total matches found")
    matches: list[SearchMatch] = Field(..., description="Search matches with context")
    truncated: bool = Field(False, description="Whether results were truncated")


class ErrorGroup(BaseModel):
    """A group of similar error messages."""

    message_template: str = Field(..., description="Template of the error message")
    count: int = Field(..., description="Number of occurrences")
    first_seen: datetime | None = Field(None, description="First occurrence timestamp")
    last_seen: datetime | None = Field(None, description="Last occurrence timestamp")
    sample_entries: list[ParsedLogEntry] = Field(..., description="Sample entries from this group")
    stack_trace: str | None = Field(None, description="Associated stack trace if present")


class ExtractErrorsResult(BaseModel):
    """Result of error extraction."""

    file_path: str = Field(..., description="Path to analyzed file")
    total_errors: int = Field(..., description="Total error count")
    total_warnings: int = Field(..., description="Total warning count")
    error_groups: list[ErrorGroup] = Field(..., description="Grouped error messages")
    unique_errors: int = Field(..., description="Number of unique error types")


class LogSummary(BaseModel):
    """Summary of log file contents."""

    file_path: str = Field(..., description="Path to summarized file")
    total_lines: int = Field(..., description="Total lines in file")
    parsed_lines: int = Field(..., description="Lines successfully parsed")
    time_span: str | None = Field(None, description="Human-readable time span")
    time_range_start: datetime | None = Field(None, description="Start of log time range")
    time_range_end: datetime | None = Field(None, description="End of log time range")
    level_distribution: dict[str, int] = Field(..., description="Entries by log level")
    top_errors: list[ErrorGroup] = Field(..., description="Most frequent errors")
    activity_pattern: str = Field(..., description="Description of activity patterns")
    recommendations: list[str] = Field(..., description="Debugging recommendations")


class TailResult(BaseModel):
    """Result of tail operation."""

    file_path: str = Field(..., description="Path to file")
    lines_returned: int = Field(..., description="Number of lines returned")
    entries: list[ParsedLogEntry] = Field(..., description="Recent log entries")


class CorrelatedEvent(BaseModel):
    """A correlated event from multiple log sources."""

    timestamp: datetime = Field(..., description="Event timestamp")
    source_file: str = Field(..., description="Source log file")
    entry: ParsedLogEntry = Field(..., description="The log entry")


class CorrelationWindow(BaseModel):
    """A window of correlated events."""

    window_start: datetime = Field(..., description="Window start time")
    window_end: datetime = Field(..., description="Window end time")
    events: list[CorrelatedEvent] = Field(..., description="Events in this window")
    summary: str = Field(..., description="Summary of correlated events")


class CorrelateResult(BaseModel):
    """Result of log correlation."""

    file_paths: list[str] = Field(..., description="Files correlated")
    time_window_seconds: int = Field(..., description="Time window used")
    correlation_windows: list[CorrelationWindow] = Field(
        ..., description="Identified correlation windows"
    )
    total_events_correlated: int = Field(..., description="Total events correlated")


class DiffResult(BaseModel):
    """Result of log diff operation."""

    file_path1: str = Field(..., description="First file path")
    file_path2: str | None = Field(None, description="Second file path if comparing files")
    time_range1: str | None = Field(None, description="First time range description")
    time_range2: str | None = Field(None, description="Second time range description")
    new_errors: list[ErrorGroup] = Field(..., description="New errors in second range/file")
    resolved_errors: list[ErrorGroup] = Field(..., description="Errors in first but not second")
    level_changes: dict[str, dict[str, int]] = Field(..., description="Changes in log level counts")
    summary: str = Field(..., description="Human-readable diff summary")
