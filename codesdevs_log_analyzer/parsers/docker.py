"""Docker/Container log parser."""

import json
import re
from datetime import datetime, timezone
from typing import ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import BaseLogParser


class DockerParser(BaseLogParser):
    """
    Parser for Docker/Container logs.

    Handles multiple formats:
    - Docker native: 2026-01-15T10:30:00.123456789Z stdout P message
    - Docker JSON: {"log":"message\n","stream":"stdout","time":"2026-01-15T10:30:00.123Z"}
    - Containerd/CRI: 2026-01-15T10:30:00.123456789Z stdout F message

    Level mapping:
    - stderr → ERROR
    - stdout → INFO
    """

    name: ClassVar[str] = "docker"
    description: ClassVar[str] = "Docker/Container log format"
    patterns: ClassVar[list[str]] = [
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+(stdout|stderr)",
        r'^\{"log":',
    ]

    # Docker native/CRI format: timestamp stream flag message
    NATIVE_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+"
        r"(?P<stream>stdout|stderr)\s+"
        r"(?P<flag>[PF])\s+"
        r"(?P<message>.*)$"
    )

    # Simpler format without flag
    SIMPLE_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+"
        r"(?P<stream>stdout|stderr)\s+"
        r"(?P<message>.*)$"
    )

    def can_parse(self, line: str) -> bool:
        """Check if line matches Docker log format."""
        if not line:
            return False

        # Check for Docker JSON format
        if line.startswith('{"log":') or line.startswith('{"stream":'):
            return True

        # Check for native format with ISO timestamp and stream
        if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line):
            return "stdout" in line[:60] or "stderr" in line[:60]

        return False

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse a Docker log line."""
        if not line:
            return None

        # Try JSON format first
        if line.startswith("{"):
            return self._parse_json_line(line, line_number)

        # Try native formats
        for pattern in [self.NATIVE_PATTERN, self.SIMPLE_PATTERN]:
            match = pattern.match(line)
            if match:
                return self._create_entry_from_match(match, line, line_number)

        return None

    def _parse_json_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse Docker JSON log format."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Extract fields
        message = data.get("log", "").rstrip("\n")
        stream = data.get("stream", "stdout")
        time_str = data.get("time", "")

        # Parse timestamp
        timestamp = self._parse_timestamp(time_str)

        # Determine level from stream
        level = LogLevel.ERROR if stream == "stderr" else LogLevel.INFO

        # Build metadata
        metadata = {
            "stream": stream,
            "format": "json",
        }

        # Include any extra fields
        for key in data:
            if key not in ("log", "stream", "time"):
                metadata[key] = data[key]

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

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

        # Get stream and determine level
        stream = groups.get("stream", "stdout")
        level = LogLevel.ERROR if stream == "stderr" else LogLevel.INFO

        # Get message
        message = groups.get("message", "").strip()

        # Build metadata
        metadata: dict[str, str | bool | None] = {
            "stream": stream,
            "format": "native",
        }

        flag = groups.get("flag")
        if flag:
            metadata["partial"] = flag == "P"

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _parse_timestamp(self, ts_str: str) -> datetime | None:
        """Parse Docker RFC3339Nano timestamp."""
        if not ts_str:
            return None

        # Handle various precision levels
        # Full: 2026-01-15T10:30:00.123456789Z
        # Short: 2026-01-15T10:30:00.123Z
        # No millis: 2026-01-15T10:30:00Z

        patterns = [
            (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{9})Z", 9),
            (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{6})Z", 6),
            (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{3})Z", 3),
            (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z", 0),
        ]

        for pattern, precision in patterns:
            match = re.match(pattern, ts_str)
            if match:
                try:
                    base_str = match.group(1)
                    dt = datetime.strptime(base_str, "%Y-%m-%dT%H:%M:%S")

                    if precision > 0:
                        # Parse fractional seconds
                        frac = match.group(2)
                        # Convert to microseconds
                        if precision == 9:
                            micros = int(frac[:6])
                        elif precision == 6:
                            micros = int(frac)
                        else:  # precision == 3
                            micros = int(frac) * 1000
                        dt = dt.replace(microsecond=micros)

                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

        return None
