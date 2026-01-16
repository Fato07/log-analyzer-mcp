"""Apache/Nginx access and error log parsers."""

import re
from datetime import datetime, timedelta, timezone
from typing import ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import BaseLogParser


class ApacheAccessParser(BaseLogParser):
    """
    Parser for Apache/Nginx combined access log format.

    Format: 127.0.0.1 - - [15/Jan/2026:10:30:00 +0000] "GET /path HTTP/1.1" 200 1234 "referer" "user-agent"

    Also handles common log format (without referer and user-agent).
    """

    name: ClassVar[str] = "apache_access"
    description: ClassVar[str] = "Apache/Nginx combined access log format"
    patterns: ClassVar[list[str]] = [
        r'^\S+\s+\S+\s+\S+\s+\[.+\]\s+"[A-Z]+\s+',
    ]

    # Combined log format pattern
    COMBINED_PATTERN = re.compile(
        r"^(?P<client_ip>\S+)\s+"
        r"(?P<ident>\S+)\s+"
        r"(?P<user>\S+)\s+"
        r"\[(?P<timestamp>[^\]]+)\]\s+"
        r'"(?P<request>[^"]*)"\s+'
        r"(?P<status>\d{3})\s+"
        r"(?P<bytes>\S+)"
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    # Month mapping for Apache date format
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

    def can_parse(self, line: str) -> bool:
        """Check if line matches Apache access log format."""
        if not line or len(line) < 30:
            return False

        # Quick checks
        if "[" not in line or "]" not in line:
            return False
        if '"' not in line:
            return False

        # Check for common HTTP methods
        return any(
            method in line
            for method in ['"GET ', '"POST ', '"PUT ', '"DELETE ', '"HEAD ', '"OPTIONS ', '"PATCH ']
        )

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse an Apache/Nginx access log line."""
        if not line:
            return None

        match = self.COMBINED_PATTERN.match(line)
        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp
        timestamp = self._parse_timestamp(groups.get("timestamp", ""))

        # Parse request
        request = groups.get("request", "")
        method, path, protocol = self._parse_request(request)

        # Parse status code and determine level
        status_str = groups.get("status", "0")
        try:
            status = int(status_str)
        except ValueError:
            status = 0

        level = self._status_to_level(status)

        # Parse bytes
        bytes_str = groups.get("bytes", "-")
        bytes_sent = int(bytes_str) if bytes_str.isdigit() else 0

        # Build message
        message = f"{method} {path} - {status}"

        # Build metadata
        metadata = {
            "client_ip": groups.get("client_ip"),
            "method": method,
            "path": path,
            "protocol": protocol,
            "status_code": status,
            "bytes_sent": bytes_sent,
            "referer": groups.get("referer") if groups.get("referer") != "-" else None,
            "user_agent": groups.get("user_agent"),
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
        """Parse Apache timestamp format: 15/Jan/2026:10:30:00 +0000"""
        if not ts_str:
            return None

        pattern = re.compile(
            r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})"
        )
        match = pattern.match(ts_str)
        if not match:
            return None

        try:
            day, month_str, year, hour, minute, second, tz_offset = match.groups()
            month = self.MONTHS.get(month_str)
            if month is None:
                return None

            # Parse timezone offset
            tz_hours = int(tz_offset[:3])
            tz_minutes = int(tz_offset[0] + tz_offset[3:5])
            tz = timezone(timedelta(hours=tz_hours, minutes=tz_minutes))

            return datetime(
                int(year),
                month,
                int(day),
                int(hour),
                int(minute),
                int(second),
                tzinfo=tz,
            )
        except (ValueError, TypeError):
            return None

    def _parse_request(self, request: str) -> tuple[str, str, str]:
        """Parse HTTP request string into method, path, protocol."""
        parts = request.split()
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        if len(parts) == 2:
            return parts[0], parts[1], ""
        if len(parts) == 1:
            return parts[0], "", ""
        return "", "", ""

    def _status_to_level(self, status: int) -> LogLevel:
        """Convert HTTP status code to log level."""
        if status >= 500:
            return LogLevel.ERROR
        if status >= 400:
            return LogLevel.WARN
        if status >= 300:
            return LogLevel.INFO
        return LogLevel.DEBUG


class ApacheErrorParser(BaseLogParser):
    """
    Parser for Apache/Nginx error log format.

    Format: [Thu Jan 15 10:30:00.123456 2026] [error] [pid 1234] [client 127.0.0.1:8080] message

    Also handles older format: [Thu Jan 15 10:30:00 2026] [error] [client 127.0.0.1] message
    """

    name: ClassVar[str] = "apache_error"
    description: ClassVar[str] = "Apache/Nginx error log format"
    patterns: ClassVar[list[str]] = [
        r"^\[[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+",
    ]

    # Error log pattern (Apache 2.4+)
    # Handles both [module:level] and [level] formats
    ERROR_PATTERN = re.compile(
        r"^\[(?P<timestamp>[^\]]+)\]\s+"
        r"\[(?:(?P<module>\w+):)?(?P<level>\w+)\]\s+"
        r"(?:\[pid\s+(?P<pid>\d+)(?::tid\s+\d+)?\]\s+)?"
        r"(?:\[client\s+(?P<client>[^\]]+)\]\s+)?"
        r"(?P<message>.*)$"
    )

    # Alternative simpler pattern
    SIMPLE_PATTERN = re.compile(
        r"^\[(?P<timestamp>[^\]]+)\]\s+"
        r"\[(?P<level>\w+)\]\s+"
        r"(?:\[client\s+(?P<client>[^\]]+)\]\s+)?"
        r"(?P<message>.*)$"
    )

    # Level mapping
    LEVEL_MAP = {
        "emerg": LogLevel.EMERGENCY,
        "alert": LogLevel.CRITICAL,
        "crit": LogLevel.CRITICAL,
        "error": LogLevel.ERROR,
        "warn": LogLevel.WARN,
        "notice": LogLevel.NOTICE,
        "info": LogLevel.INFO,
        "debug": LogLevel.DEBUG,
    }

    def can_parse(self, line: str) -> bool:
        """Check if line matches Apache error log format."""
        if not line or len(line) < 20:
            return False

        # Must start with [
        if not line.startswith("["):
            return False

        # Should have at least two bracketed sections
        bracket_count = line.count("[")
        return bracket_count >= 2

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse an Apache error log line."""
        if not line:
            return None

        # Try main pattern first
        match = self.ERROR_PATTERN.match(line)
        if not match:
            match = self.SIMPLE_PATTERN.match(line)

        if not match:
            return None

        groups = match.groupdict()

        # Parse timestamp
        timestamp = self._parse_timestamp(groups.get("timestamp", ""))

        # Get level
        level_str = groups.get("level", "").lower()
        level = self.LEVEL_MAP.get(level_str, LogLevel.ERROR)

        # Get message
        message = groups.get("message", "").strip()

        # Build metadata
        metadata: dict[str, str | int | None] = {
            "module": groups.get("module"),
        }

        if groups.get("pid"):
            metadata["pid"] = int(groups["pid"])

        client = groups.get("client")
        if client:
            # Split client IP and port
            if ":" in client:
                ip, port = client.rsplit(":", 1)
                metadata["client_ip"] = ip
                if port.isdigit():
                    metadata["client_port"] = int(port)
            else:
                metadata["client_ip"] = client

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _parse_timestamp(self, ts_str: str) -> datetime | None:
        """Parse Apache error log timestamp."""
        if not ts_str:
            return None

        # Format: Thu Jan 15 10:30:00.123456 2026
        # Or: Thu Jan 15 10:30:00 2026
        pattern = re.compile(
            r"[A-Z][a-z]{2}\s+"
            r"(?P<month>[A-Z][a-z]{2})\s+"
            r"(?P<day>\d{1,2})\s+"
            r"(?P<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
            r"(?P<year>\d{4})"
        )
        match = pattern.search(ts_str)
        if not match:
            return None

        try:
            groups = match.groupdict()
            month_map = {
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

            month = month_map.get(groups["month"])
            if month is None:
                return None

            hour, minute, second = map(int, groups["time"].split(":"))

            return datetime(
                int(groups["year"]),
                month,
                int(groups["day"]),
                hour,
                minute,
                second,
            )
        except (ValueError, TypeError, KeyError):
            return None
