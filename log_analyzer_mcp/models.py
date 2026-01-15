"""Pydantic models for log analyzer MCP server."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class LogFormat(str, Enum):
    """Supported log formats."""
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
    """Output format for responses."""
    MARKDOWN = "markdown"
    JSON = "json"


class LogLevel(str, Enum):
    """Log severity levels."""
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    FATAL = "FATAL"
    EMERGENCY = "EMERGENCY"

    @classmethod
    def normalize(cls, level: str) -> "LogLevel":
        """Normalize log level string to enum."""
        level_upper = level.upper().strip()
        # Handle common aliases
        aliases = {
            "WARN": cls.WARNING,
            "ERR": cls.ERROR,
            "CRIT": cls.CRITICAL,
            "EMERG": cls.EMERGENCY,
        }
        if level_upper in aliases:
            return aliases[level_upper]
        try:
            return cls(level_upper)
        except ValueError:
            return cls.INFO

    def is_error_level(self) -> bool:
        """Check if this level represents an error."""
        return self in (
            LogLevel.ERROR,
            LogLevel.CRITICAL,
            LogLevel.FATAL,
            LogLevel.EMERGENCY,
        )

    def is_warning_level(self) -> bool:
        """Check if this level represents a warning."""
        return self in (LogLevel.WARNING, LogLevel.WARN)


class ParsedLogEntry(BaseModel):
    """A single parsed log entry."""
    line_number: int = Field(..., description="Line number in the source file")
    raw_line: str = Field(..., description="Original unparsed line")
    timestamp: Optional[datetime] = Field(None, description="Parsed timestamp")
    level: Optional[str] = Field(None, description="Log level (ERROR, WARN, INFO, etc.)")
    message: str = Field(..., description="Log message content")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Parser-specific fields (hostname, pid, etc.)"
    )

    class Config:
        """Pydantic config."""
        extra = "allow"


class FileInfo(BaseModel):
    """Information about a log file."""
    path: str = Field(..., description="File path")
    size_bytes: int = Field(..., description="File size in bytes")
    total_lines: int = Field(..., description="Total number of lines")
    detected_format: LogFormat = Field(..., description="Detected log format")
    encoding: str = Field(default="utf-8", description="File encoding")


class TimeRange(BaseModel):
    """A time range."""
    start: Optional[datetime] = Field(None, description="Start of time range")
    end: Optional[datetime] = Field(None, description="End of time range")

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get duration in seconds."""
        if self.start and self.end:
            return (self.end - self.start).total_seconds()
        return None


class Anomaly(BaseModel):
    """A detected anomaly in log data."""
    type: str = Field(..., description="Type of anomaly (spike, gap, unusual_level)")
    description: str = Field(..., description="Human-readable description")
    severity: str = Field(default="medium", description="Severity: low, medium, high")
    timestamp: Optional[datetime] = Field(None, description="When the anomaly occurred")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")


# Input models for MCP tools
class ParseInput(BaseModel):
    """Input for log_analyzer_parse tool."""
    file_path: str = Field(..., description="Path to the log file")
    format: LogFormat = Field(
        default=LogFormat.AUTO,
        description="Log format (auto-detect if not specified)"
    )
    max_lines: int = Field(
        default=10000,
        description="Maximum lines to process"
    )


class SearchInput(BaseModel):
    """Input for log_analyzer_search tool."""
    file_path: str = Field(..., description="Path to the log file")
    pattern: str = Field(..., description="Search pattern (regex or plain text)")
    regex: bool = Field(default=True, description="Treat pattern as regex")
    case_sensitive: bool = Field(default=False, description="Case-sensitive search")
    context_before: int = Field(default=2, description="Lines of context before match")
    context_after: int = Field(default=2, description="Lines of context after match")
    max_matches: int = Field(default=100, description="Maximum matches to return")
    level_filter: Optional[list[str]] = Field(
        None,
        description="Filter by log levels"
    )
    time_start: Optional[datetime] = Field(None, description="Filter start time")
    time_end: Optional[datetime] = Field(None, description="Filter end time")


class ExtractErrorsInput(BaseModel):
    """Input for log_analyzer_extract_errors tool."""
    file_path: str = Field(..., description="Path to the log file")
    include_warnings: bool = Field(default=True, description="Include warnings")
    max_errors: int = Field(default=50, description="Maximum error groups to return")
    group_similar: bool = Field(default=True, description="Group similar errors")


class SummarizeInput(BaseModel):
    """Input for log_analyzer_summarize tool."""
    file_path: str = Field(..., description="Path to the log file")
    include_performance: bool = Field(default=True, description="Include performance metrics")
    include_security: bool = Field(default=True, description="Include security indicators")


class TailInput(BaseModel):
    """Input for log_analyzer_tail tool."""
    file_path: str = Field(..., description="Path to the log file")
    lines: int = Field(default=50, description="Number of lines to return")
    level_filter: Optional[list[str]] = Field(None, description="Filter by log levels")


class CorrelateInput(BaseModel):
    """Input for log_analyzer_correlate tool."""
    file_path: str = Field(..., description="Path to the log file")
    anchor_pattern: str = Field(..., description="Pattern to find anchor events")
    window_before: int = Field(default=60, description="Seconds before anchor to analyze")
    window_after: int = Field(default=30, description="Seconds after anchor to analyze")
    max_anchors: int = Field(default=10, description="Maximum anchor events to analyze")


class DiffInput(BaseModel):
    """Input for log_analyzer_diff tool."""
    file_path_1: str = Field(..., description="First log file path")
    file_path_2: Optional[str] = Field(None, description="Second log file path")
    time_start_1: Optional[datetime] = Field(None, description="Start time for first period")
    time_end_1: Optional[datetime] = Field(None, description="End time for first period")
    time_start_2: Optional[datetime] = Field(None, description="Start time for second period")
    time_end_2: Optional[datetime] = Field(None, description="End time for second period")
