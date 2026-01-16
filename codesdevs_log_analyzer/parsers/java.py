"""Java/Log4j logging format parser."""

import re
from datetime import datetime
from typing import ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import MultiLineParser


class JavaLogParser(MultiLineParser):
    """
    Parser for Java/Log4j logging format.

    Handles common patterns:
    - Log4j: 2026-01-15 10:30:00,123 ERROR [main] com.example.Class - Message
    - Logback: 2026-01-15 10:30:00.123 [main] ERROR c.e.Class - Message
    - Simple: 2026-01-15 10:30:00 ERROR ClassName: Message

    Also handles Java stack traces (multi-line).
    """

    name: ClassVar[str] = "java"
    description: ClassVar[str] = "Java/Log4j logging format"
    patterns: ClassVar[list[str]] = [
        r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3}\s+[A-Z]+\s+\[",
        r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3}\s+\[[^\]]+\]\s+[A-Z]+",
    ]

    # Log4j pattern: timestamp LEVEL [thread] logger - message
    LOG4J_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3})\s+"
        r"(?P<level>[A-Z]+)\s+"
        r"\[(?P<thread>[^\]]+)\]\s+"
        r"(?P<logger>\S+)\s*"
        r"[-–]\s*"
        r"(?P<message>.*)$"
    )

    # Logback pattern: timestamp [thread] LEVEL logger - message
    LOGBACK_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3})\s+"
        r"\[(?P<thread>[^\]]+)\]\s+"
        r"(?P<level>[A-Z]+)\s+"
        r"(?P<logger>\S+)\s*"
        r"[-–]\s*"
        r"(?P<message>.*)$"
    )

    # Simple pattern: timestamp LEVEL logger message
    SIMPLE_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,\.]\d{3})?)\s+"
        r"(?P<level>[A-Z]+)\s+"
        r"(?P<logger>\S+?)(?::\s*|\s+[-–]\s*|\s+)"
        r"(?P<message>.*)$"
    )

    # Stack trace patterns
    STACK_FRAME = re.compile(r"^\s+at\s+[\w.$]+\([^)]*\)")
    CAUSED_BY = re.compile(r"^Caused by:\s+")
    EXCEPTION_LINE = re.compile(r"^[\w.]+(?:Exception|Error|Throwable):\s*")
    MORE_LINE = re.compile(r"^\s*\.\.\.\s+\d+\s+more")

    def can_parse(self, line: str) -> bool:
        """Check if line matches Java log format."""
        if not line:
            return False

        # Check for standard patterns
        for pattern in [self.LOG4J_PATTERN, self.LOGBACK_PATTERN, self.SIMPLE_PATTERN]:
            if pattern.match(line):
                return True

        # Check for stack trace start
        return bool(self.EXCEPTION_LINE.match(line))

    def is_continuation(self, line: str) -> bool:
        """Check if line is a stack trace continuation."""
        if not line:
            return False

        # Stack frame: "    at com.example.Class.method(File.java:123)"
        if self.STACK_FRAME.match(line):
            return True

        # Caused by line
        if self.CAUSED_BY.match(line):
            return True

        # "... N more" lines
        if self.MORE_LINE.match(line):
            return True

        # Tab-indented continuation
        return line.startswith("\t") or line.startswith("        ")

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse a Java log line."""
        if not line:
            return None

        # Try each pattern
        for pattern in [self.LOG4J_PATTERN, self.LOGBACK_PATTERN, self.SIMPLE_PATTERN]:
            match = pattern.match(line)
            if match:
                return self._create_entry_from_match(match, line, line_number)

        # Handle exception line
        if self.EXCEPTION_LINE.match(line):
            return self.create_entry(
                line_number=line_number,
                raw_line=line,
                message=line,
                level=LogLevel.ERROR,
                metadata={"is_exception_start": True},
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
        timestamp = self._parse_timestamp(groups.get("timestamp", ""))

        # Get level
        level_str = groups.get("level", "")
        level = self.normalize_level(level_str)

        # Get message
        message = groups.get("message", "").strip()

        # Build metadata
        metadata: dict[str, str | None] = {
            "thread": groups.get("thread"),
            "logger": groups.get("logger"),
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
        """Parse Java logging timestamp."""
        if not ts_str:
            return None

        # Normalize separators
        ts_str = ts_str.replace(",", ".")

        for fmt in [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                # Handle 3-digit milliseconds
                if "." in ts_str:
                    parts = ts_str.split(".")
                    if len(parts[-1]) == 3:
                        ts_str = parts[0] + "." + parts[1] + "000"
                return datetime.strptime(ts_str[:26], fmt)
            except ValueError:
                continue

        return None
