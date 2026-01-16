"""Error extractor analyzer - Extract and group errors from logs."""

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..parsers.base import BaseLogParser, ParsedLogEntry

# Output limits
MAX_ERRORS = 50
MAX_SAMPLE_ENTRIES = 3
MAX_STACK_TRACE_LINES = 30


@dataclass
class ErrorGroup:
    """A group of similar errors."""

    template: str  # Normalized message
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sample_entries: list[ParsedLogEntry] = field(default_factory=list)
    stack_trace: str | None = None
    levels: set[str] = field(default_factory=set)

    def add_entry(self, entry: ParsedLogEntry, stack_trace: str | None = None) -> None:
        """Add an entry to this error group."""
        self.count += 1

        if entry.timestamp:
            if self.first_seen is None or entry.timestamp < self.first_seen:
                self.first_seen = entry.timestamp
            if self.last_seen is None or entry.timestamp > self.last_seen:
                self.last_seen = entry.timestamp

        if entry.level:
            self.levels.add(entry.level.upper())

        if len(self.sample_entries) < MAX_SAMPLE_ENTRIES:
            self.sample_entries.append(entry)

        if stack_trace and not self.stack_trace:
            # Truncate stack trace if too long
            lines = stack_trace.split("\n")
            if len(lines) > MAX_STACK_TRACE_LINES:
                lines = lines[:MAX_STACK_TRACE_LINES] + ["... (truncated)"]
            self.stack_trace = "\n".join(lines)


@dataclass
class ErrorExtractionResult:
    """Result of error extraction."""

    total_errors: int = 0
    total_warnings: int = 0
    unique_errors: int = 0
    error_groups: list[ErrorGroup] = field(default_factory=list)
    time_range: tuple[datetime | None, datetime | None] = (None, None)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_errors": self.total_errors,
            "total_warnings": self.total_warnings,
            "unique_errors": self.unique_errors,
            "error_groups": [
                {
                    "template": g.template,
                    "count": g.count,
                    "first_seen": g.first_seen.isoformat() if g.first_seen else None,
                    "last_seen": g.last_seen.isoformat() if g.last_seen else None,
                    "sample_entries": [
                        {
                            "line_number": e.line_number,
                            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                            "level": e.level,
                            "message": e.message[:500],  # Truncate long messages
                        }
                        for e in g.sample_entries
                    ],
                    "stack_trace": g.stack_trace,
                    "levels": list(g.levels),
                }
                for g in self.error_groups
            ],
            "time_range": {
                "start": self.time_range[0].isoformat() if self.time_range[0] else None,
                "end": self.time_range[1].isoformat() if self.time_range[1] else None,
            },
        }


def normalize_error_message(message: str) -> str:
    """
    Normalize error messages for grouping.
    Replace variable parts with placeholders:
    - UUIDs → <UUID>
    - Numbers → <N>
    - File paths → <PATH>
    - Timestamps → <TIME>
    - IP addresses → <IP>
    - Hex values → <HEX>
    - Memory addresses → <ADDR>
    """
    result = message

    # Replace UUIDs (8-4-4-4-12 hex format)
    result = re.sub(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "<UUID>",
        result,
    )

    # Replace IP addresses (IPv4)
    result = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", result)

    # Replace timestamps (various formats)
    # ISO 8601
    result = re.sub(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "<TIME>", result
    )
    # Other timestamp formats
    result = re.sub(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}", "<TIME>", result)
    result = re.sub(r"\d{2}:\d{2}:\d{2}(?:,\d+)?", "<TIME>", result)

    # Replace file paths (Unix and Windows)
    result = re.sub(r"(?:/[\w\-\.]+)+(?:/[\w\-\.]*)?", "<PATH>", result)
    result = re.sub(r"[A-Za-z]:\\(?:[\w\-\.]+\\)*[\w\-\.]*", "<PATH>", result)

    # Replace hex values (0x...)
    result = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", result)

    # Replace memory addresses
    result = re.sub(r"\bat 0x[0-9a-fA-F]+\b", "at <ADDR>", result)

    # Replace numbers (but preserve numbers in common error codes)
    # First, protect error codes like "404", "500", "E1234"
    protected = {}
    for i, match in enumerate(re.finditer(r"\b[A-Z]?\d{3,4}\b", result)):
        placeholder = f"__ERROR_CODE_{i}__"
        protected[placeholder] = match.group()
        result = result.replace(match.group(), placeholder, 1)

    # Now replace remaining numbers
    result = re.sub(r"\b\d+\b", "<N>", result)

    # Restore protected error codes
    for placeholder, original in protected.items():
        result = result.replace(placeholder, original)

    # Collapse multiple spaces
    result = re.sub(r"\s+", " ", result)

    return result.strip()


class ErrorExtractor:
    """
    Streaming error extractor that groups similar errors.
    Memory-efficient: processes entries one at a time.
    """

    # Error level keywords
    ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL", "EMERGENCY", "SEVERE"}
    WARNING_LEVELS = {"WARN", "WARNING"}

    # Stack trace detection patterns
    STACK_TRACE_PATTERNS = [
        re.compile(r"^Traceback \(most recent call last\):"),  # Python
        re.compile(r"^\s+at\s+[\w\.$]+\("),  # Java/JavaScript
        re.compile(r'^\s+File\s+"[^"]+",\s+line\s+\d+'),  # Python stack frame
        re.compile(r"^Caused by:"),  # Java cause chain
        re.compile(r"^\s+\.{3}\s+\d+\s+more"),  # Java truncated stack
        re.compile(r"^\s+at\s+"),  # Generic "at" lines
    ]

    # Exception type patterns
    EXCEPTION_PATTERNS = [
        re.compile(r"^(\w+(?:\.\w+)*(?:Error|Exception|Failure))[:\s]"),  # Python/Java
        re.compile(r"^(\w+Exception):"),  # Java exceptions
        re.compile(r"^(\w+Error):"),  # General errors
        re.compile(r"Caused by:\s*(\w+(?:\.\w+)*(?:Error|Exception))"),  # Java caused by
    ]

    def __init__(
        self,
        include_warnings: bool = True,
        max_errors: int = MAX_ERRORS,
        group_similar: bool = True,
    ):
        """
        Initialize error extractor.

        Args:
            include_warnings: Whether to include warnings in extraction
            max_errors: Maximum number of error groups to track
            group_similar: Whether to group similar errors
        """
        self.include_warnings = include_warnings
        self.max_errors = max_errors
        self.group_similar = group_similar

        # State
        self._error_groups: dict[str, ErrorGroup] = {}
        self._total_errors = 0
        self._total_warnings = 0
        self._time_start: datetime | None = None
        self._time_end: datetime | None = None

        # Stack trace accumulation
        self._pending_error: ParsedLogEntry | None = None
        self._stack_trace_lines: list[str] = []

    def _is_error_level(self, level: str | None) -> bool:
        """Check if level indicates an error."""
        if not level:
            return False
        return level.upper() in self.ERROR_LEVELS

    def _is_warning_level(self, level: str | None) -> bool:
        """Check if level indicates a warning."""
        if not level:
            return False
        return level.upper() in self.WARNING_LEVELS

    def _is_stack_trace_line(self, line: str) -> bool:
        """Check if line is part of a stack trace."""
        return any(pattern.match(line) for pattern in self.STACK_TRACE_PATTERNS)

    def _update_time_range(self, timestamp: datetime | None) -> None:
        """Update the tracked time range."""
        if timestamp:
            if self._time_start is None or timestamp < self._time_start:
                self._time_start = timestamp
            if self._time_end is None or timestamp > self._time_end:
                self._time_end = timestamp

    def _flush_pending_error(self) -> None:
        """Process any pending error with accumulated stack trace."""
        if self._pending_error is None:
            return

        entry = self._pending_error
        stack_trace = "\n".join(self._stack_trace_lines) if self._stack_trace_lines else None

        # Get template for grouping
        template = normalize_error_message(entry.message) if self.group_similar else entry.message

        # Add to group
        if template not in self._error_groups and len(self._error_groups) < self.max_errors:
            self._error_groups[template] = ErrorGroup(template=template)

        if template in self._error_groups:
            self._error_groups[template].add_entry(entry, stack_trace)

        # Reset pending state
        self._pending_error = None
        self._stack_trace_lines = []

    def process_entry(self, entry: ParsedLogEntry) -> None:
        """
        Process a single log entry.

        Args:
            entry: Parsed log entry to process
        """
        self._update_time_range(entry.timestamp)

        # Check if this is a continuation of a stack trace
        if self._pending_error is not None:
            if self._is_stack_trace_line(entry.raw_line):
                self._stack_trace_lines.append(entry.raw_line)
                return
            else:
                # Stack trace ended, flush the pending error
                self._flush_pending_error()

        # Check if this is an error or warning
        is_error = self._is_error_level(entry.level)
        is_warning = self._is_warning_level(entry.level)

        if is_error:
            self._total_errors += 1
            self._pending_error = entry
            self._stack_trace_lines = []
        elif is_warning and self.include_warnings:
            self._total_warnings += 1
            self._pending_error = entry
            self._stack_trace_lines = []

    def finalize(self) -> ErrorExtractionResult:
        """
        Finalize extraction and return results.

        Returns:
            ErrorExtractionResult with all extracted errors
        """
        # Flush any pending error
        self._flush_pending_error()

        # Sort error groups by count (most frequent first)
        sorted_groups = sorted(self._error_groups.values(), key=lambda g: g.count, reverse=True)

        return ErrorExtractionResult(
            total_errors=self._total_errors,
            total_warnings=self._total_warnings,
            unique_errors=len(sorted_groups),
            error_groups=sorted_groups,
            time_range=(self._time_start, self._time_end),
        )

    def analyze_file(
        self, parser: BaseLogParser, file_path: str, max_lines: int = 10000
    ) -> ErrorExtractionResult:
        """
        Stream analyze a file for errors.

        Args:
            parser: Parser to use for parsing log entries
            file_path: Path to the log file
            max_lines: Maximum lines to process

        Returns:
            ErrorExtractionResult with all extracted errors
        """
        for entry in parser.parse_file(file_path, max_lines=max_lines):
            self.process_entry(entry)
        return self.finalize()

    def analyze_entries(self, entries: Iterator[ParsedLogEntry]) -> ErrorExtractionResult:
        """
        Analyze an iterator of entries.

        Args:
            entries: Iterator of parsed log entries

        Returns:
            ErrorExtractionResult with all extracted errors
        """
        for entry in entries:
            self.process_entry(entry)
        return self.finalize()


def extract_errors(
    parser: BaseLogParser,
    file_path: str,
    include_warnings: bool = True,
    max_errors: int = MAX_ERRORS,
    group_similar: bool = True,
    max_lines: int = 10000,
) -> ErrorExtractionResult:
    """
    Convenience function to extract errors from a log file.

    Args:
        parser: Parser to use for parsing log entries
        file_path: Path to the log file
        include_warnings: Whether to include warnings
        max_errors: Maximum number of error groups
        group_similar: Whether to group similar errors
        max_lines: Maximum lines to process

    Returns:
        ErrorExtractionResult with all extracted errors
    """
    extractor = ErrorExtractor(
        include_warnings=include_warnings, max_errors=max_errors, group_similar=group_similar
    )
    return extractor.analyze_file(parser, file_path, max_lines=max_lines)
