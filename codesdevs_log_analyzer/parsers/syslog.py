"""Syslog format parser."""

import re
from datetime import datetime
from typing import ClassVar

from dateutil.tz import tzlocal

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import BaseLogParser


class SyslogParser(BaseLogParser):
    """
    Parser for syslog format logs.

    Format: Jan 15 10:30:00 hostname process[pid]: message

    Examples:
        Jan 15 10:30:00 myhost sshd[1234]: Accepted password for user
        Feb  3 08:15:30 server kernel: [12345.678901] Network device up
    """

    name: ClassVar[str] = "syslog"
    description: ClassVar[str] = "Standard syslog format (RFC 3164)"
    patterns: ClassVar[list[str]] = [
        r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
    ]

    # Main syslog pattern
    SYSLOG_PATTERN = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)$"
    )

    # Month mapping
    MONTHS = {
        "Jan": 1,
        "Feb": 2,
        "Mar": 3,
        "Apr": 4,
        "May": 5,
        "Jun": 6,
        "Jul": 7,
        "Aug": 8,
        "Sep": 9,
        "Oct": 10,
        "Nov": 11,
        "Dec": 12,
    }

    # Facility and severity detection patterns
    LEVEL_PATTERNS = {
        LogLevel.EMERGENCY: re.compile(r"\b(emerg|emergency|panic)\b", re.I),
        LogLevel.CRITICAL: re.compile(r"\b(crit|critical)\b", re.I),
        LogLevel.ERROR: re.compile(r"\b(err|error|fail|failed|failure)\b", re.I),
        LogLevel.WARN: re.compile(r"\b(warn|warning)\b", re.I),
        LogLevel.NOTICE: re.compile(r"\b(notice)\b", re.I),
        LogLevel.INFO: re.compile(r"\b(info)\b", re.I),
        LogLevel.DEBUG: re.compile(r"\b(debug)\b", re.I),
    }

    def can_parse(self, line: str) -> bool:
        """Check if line matches syslog format."""
        if not line or len(line) < 15:
            return False

        # Quick check for month at start
        month_part = line[:3]
        return month_part in self.MONTHS

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse a syslog line."""
        if not line:
            return None

        match = self.SYSLOG_PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp
        timestamp = self._parse_timestamp(
            groups["month"],
            groups["day"],
            groups["time"],
        )

        # Extract message and detect level
        message = groups["message"] or ""
        level = self._detect_level(message, groups.get("process", ""))

        # Build metadata
        metadata: dict[str, str | int | None] = {
            "hostname": groups.get("hostname"),
            "process": groups.get("process"),
        }
        if groups.get("pid"):
            metadata["pid"] = int(groups["pid"])

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _parse_timestamp(
        self,
        month_str: str,
        day_str: str,
        time_str: str,
    ) -> datetime | None:
        """Parse syslog timestamp components."""
        try:
            month = self.MONTHS.get(month_str)
            if month is None:
                return None

            day = int(day_str)
            hour, minute, second = map(int, time_str.split(":"))

            return datetime(
                self.default_year,
                month,
                day,
                hour,
                minute,
                second,
                tzinfo=tzlocal(),
            )
        except (ValueError, TypeError):
            return None

    def _detect_level(self, message: str, process: str) -> LogLevel | None:
        """Detect log level from message or process name."""
        # Check message for level indicators
        for level, pattern in self.LEVEL_PATTERNS.items():
            if pattern.search(message):
                return level

        # Check common process names
        if process.lower() in ("error", "err"):
            return LogLevel.ERROR

        return None
