"""Base parser interface for all log format parsers."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import datetime
from typing import Any, ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.utils.file_handler import stream_file

__all__ = ["BaseLogParser", "ParsedLogEntry", "LogLevel"]


class BaseLogParser(ABC):
    """
    Abstract base class for all log format parsers.

    Subclasses must implement:
    - name: Parser identifier
    - patterns: List of regex patterns this parser handles
    - can_parse(): Check if parser can handle a line
    - parse_line(): Parse a single log line
    """

    # Class-level attributes
    name: ClassVar[str] = "base"
    description: ClassVar[str] = "Base log parser"
    patterns: ClassVar[list[str]] = []

    def __init__(self, default_year: int | None = None) -> None:
        """
        Initialize parser.

        Args:
            default_year: Year to use for timestamps without year (e.g., syslog)
        """
        self.default_year = default_year or datetime.now().year

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """
        Check if this parser can handle the given line.

        This should be a fast check used for format detection.

        Args:
            line: Raw log line

        Returns:
            True if this parser can likely handle the line
        """
        ...

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """
        Parse a single log line.

        Args:
            line: Raw log line
            line_number: 1-indexed line number

        Returns:
            ParsedLogEntry if successfully parsed, None otherwise
        """
        ...

    def parse_file(
        self,
        file_path: str,
        max_lines: int | None = None,
        encoding: str | None = None,
    ) -> Iterator[ParsedLogEntry]:
        """
        Stream parse a log file.

        Args:
            file_path: Path to log file
            max_lines: Maximum lines to parse (None for all)
            encoding: File encoding (auto-detected if None)

        Yields:
            ParsedLogEntry for each successfully parsed line
        """
        for line_num, line in stream_file(file_path, encoding=encoding, max_lines=max_lines):
            entry = self.parse_line(line, line_num)
            if entry is not None:
                yield entry

    @classmethod
    def detect_confidence(cls, sample_lines: list[str]) -> float:
        """
        Return confidence score (0.0-1.0) for format detection.

        Analyzes sample lines to determine how well this parser
        matches the log format.

        Args:
            sample_lines: List of sample log lines

        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not sample_lines:
            return 0.0

        # Create temporary instance for parsing
        parser = cls()

        # Count successfully parsed lines
        parsed_count: float = 0
        can_parse_count = 0

        for line in sample_lines:
            if not line.strip():
                continue

            if parser.can_parse(line):
                can_parse_count += 1

            entry = parser.parse_line(line, 0)
            if entry is not None:
                # Check if we extracted meaningful data
                if entry.timestamp is not None or entry.level is not None:
                    parsed_count += 1
                elif entry.message != entry.raw_line:
                    # Parser extracted something different from raw line
                    parsed_count += 0.5

        total_lines = len([line for line in sample_lines if line.strip()])
        if total_lines == 0:
            return 0.0

        # Weight both can_parse and actual parsing success
        can_parse_ratio = can_parse_count / total_lines
        parse_ratio = parsed_count / total_lines

        # Combined score with higher weight on actual parsing
        return min(1.0, can_parse_ratio * 0.3 + parse_ratio * 0.7)

    def normalize_level(self, level_str: str | None) -> LogLevel | None:
        """
        Normalize a log level string to LogLevel enum.

        Args:
            level_str: Raw level string from log

        Returns:
            Normalized LogLevel or None
        """
        return LogLevel.normalize(level_str)

    def create_entry(
        self,
        line_number: int,
        raw_line: str,
        message: str,
        timestamp: datetime | None = None,
        level: LogLevel | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ParsedLogEntry:
        """
        Helper to create a ParsedLogEntry.

        Args:
            line_number: Line number in source file
            raw_line: Original raw line
            message: Extracted message
            timestamp: Parsed timestamp
            level: Log level
            metadata: Additional parser-specific fields

        Returns:
            ParsedLogEntry instance
        """
        return ParsedLogEntry(
            line_number=line_number,
            raw_line=raw_line,
            timestamp=timestamp,
            level=level,
            message=message,
            metadata=metadata or {},
        )

    def __repr__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}(name={self.name!r})"


class MultiLineParser(BaseLogParser):
    """
    Base class for parsers that handle multi-line log entries.

    Subclasses should implement is_continuation() to detect continuation lines.
    """

    @abstractmethod
    def is_continuation(self, line: str) -> bool:
        """
        Check if line is a continuation of previous entry.

        Used for multi-line entries like stack traces.

        Args:
            line: Log line to check

        Returns:
            True if this is a continuation line
        """
        ...

    def parse_file(
        self,
        file_path: str,
        max_lines: int | None = None,
        encoding: str | None = None,
    ) -> Iterator[ParsedLogEntry]:
        """
        Stream parse with multi-line support.

        Accumulates continuation lines with their parent entry.
        """
        current_entry: ParsedLogEntry | None = None
        continuation_lines: list[str] = []

        for line_num, line in stream_file(file_path, encoding=encoding, max_lines=max_lines):
            if self.is_continuation(line):
                # Accumulate continuation line
                continuation_lines.append(line)
                continue

            # Not a continuation - emit previous entry if exists
            if current_entry is not None:
                if continuation_lines:
                    # Append continuations to message
                    full_message = current_entry.message + "\n" + "\n".join(continuation_lines)
                    current_entry = self.create_entry(
                        line_number=current_entry.line_number,
                        raw_line=current_entry.raw_line,
                        message=full_message,
                        timestamp=current_entry.timestamp,
                        level=current_entry.level,
                        metadata={
                            **current_entry.metadata,
                            "continuation_lines": len(continuation_lines),
                        },
                    )
                yield current_entry

            # Parse new entry
            current_entry = self.parse_line(line, line_num)
            continuation_lines = []

        # Emit final entry
        if current_entry is not None:
            if continuation_lines:
                full_message = current_entry.message + "\n" + "\n".join(continuation_lines)
                current_entry = self.create_entry(
                    line_number=current_entry.line_number,
                    raw_line=current_entry.raw_line,
                    message=full_message,
                    timestamp=current_entry.timestamp,
                    level=current_entry.level,
                    metadata={
                        **current_entry.metadata,
                        "continuation_lines": len(continuation_lines),
                    },
                )
            yield current_entry
