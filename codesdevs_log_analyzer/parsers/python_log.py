"""Python logging format parser."""

import re
from datetime import datetime
from typing import ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import MultiLineParser


class PythonLogParser(MultiLineParser):
    """
    Parser for Python standard library logging format.

    Handles multiple common formats:
    - Default: 2026-01-15 10:30:00,123 - module.name - ERROR - Message text
    - Basic: ERROR:module.name:Message text
    - With brackets: [2026-01-15 10:30:00] ERROR module: Message

    Also handles stack traces (multi-line).
    """

    name: ClassVar[str] = "python"
    description: ClassVar[str] = "Python standard logging format"
    patterns: ClassVar[list[str]] = [
        r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}",
        r"^[A-Z]+:\S+:",
        r"^\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\]",
    ]

    # Default format: 2026-01-15 10:30:00,123 - module - LEVEL - message
    DEFAULT_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,\.]\d{3})?)\s*"
        r"[-–]\s*"
        r"(?P<module>\S+)\s*"
        r"[-–]\s*"
        r"(?P<level>[A-Z]+)\s*"
        r"[-–]\s*"
        r"(?P<message>.*)$"
    )

    # Basic format: LEVEL:module:message
    BASIC_PATTERN = re.compile(r"^(?P<level>[A-Z]+):(?P<module>[^:]+):(?P<message>.*)$")

    # Bracket format: [2026-01-15 10:30:00] LEVEL module: message
    BRACKET_PATTERN = re.compile(
        r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,\.]\d{3})?)\]\s*"
        r"(?P<level>[A-Z]+)\s+"
        r"(?P<module>\S+?):\s*"
        r"(?P<message>.*)$"
    )

    # Alternative with level first: ERROR 2026-01-15 10:30:00,123 module - message
    ALT_PATTERN = re.compile(
        r"^(?P<level>[A-Z]+)\s+"
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,\.]\d{3})?)\s+"
        r"(?P<module>\S+)\s*"
        r"[-–]\s*"
        r"(?P<message>.*)$"
    )

    # Stack trace patterns
    TRACEBACK_START = re.compile(r"^Traceback \(most recent call last\):")
    STACK_FRAME = re.compile(r'^\s+File ".*", line \d+')
    EXCEPTION_LINE = re.compile(r"^[A-Z][a-zA-Z]*(?:Error|Exception|Warning):")

    def can_parse(self, line: str) -> bool:
        """Check if line matches Python log format."""
        if not line:
            return False

        # Check for standard patterns
        for pattern in [
            self.DEFAULT_PATTERN,
            self.BASIC_PATTERN,
            self.BRACKET_PATTERN,
            self.ALT_PATTERN,
        ]:
            if pattern.match(line):
                return True

        # Check for traceback
        return bool(self.TRACEBACK_START.match(line))

    def is_continuation(self, line: str) -> bool:
        """Check if line is a stack trace continuation."""
        if not line:
            return False

        # Traceback start - treat as continuation of previous error log
        if self.TRACEBACK_START.match(line):
            return True

        # Stack trace frame
        if self.STACK_FRAME.match(line):
            return True

        # Indented continuation
        if line.startswith("    ") or line.startswith("\t"):
            return True

        # Exception line at end of traceback
        if self.EXCEPTION_LINE.match(line):
            return True

        # Continuation of multi-line message
        return line.startswith("  ")

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse a Python log line."""
        if not line:
            return None

        # Try each pattern
        for pattern in [
            self.DEFAULT_PATTERN,
            self.BRACKET_PATTERN,
            self.ALT_PATTERN,
            self.BASIC_PATTERN,
        ]:
            match = pattern.match(line)
            if match:
                return self._create_entry_from_match(match, line, line_number)

        # Handle traceback start
        if self.TRACEBACK_START.match(line):
            return self.create_entry(
                line_number=line_number,
                raw_line=line,
                message=line,
                level=LogLevel.ERROR,
                metadata={"is_traceback_start": True},
            )

        return None

    def _create_entry_from_match(
        self,
        match: re.Match[str],
        line: str,
        line_number: int,
    ) -> ParsedLogEntry:
        """Create entry from regex match."""
        groups = match.groupdict()

        # Parse timestamp
        timestamp = None
        ts_str = groups.get("timestamp")
        if ts_str:
            timestamp = self._parse_timestamp(ts_str)

        # Get level
        level_str = groups.get("level", "")
        level = self.normalize_level(level_str)

        # Get message
        message = groups.get("message", "").strip()

        # Build metadata
        metadata: dict[str, str | None] = {
            "module": groups.get("module"),
        }

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _parse_timestamp(self, ts_str: str) -> datetime | None:
        """Parse Python logging timestamp."""
        if not ts_str:
            return None

        # Normalize separator
        ts_str = ts_str.replace(",", ".")

        # Try parsing with microseconds
        for fmt in [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                # Handle 3-digit milliseconds
                if "." in ts_str and len(ts_str.split(".")[-1]) == 3:
                    ts_str = ts_str + "000"  # Pad to microseconds
                return datetime.strptime(ts_str[:26], fmt)
            except ValueError:
                continue

        return None
