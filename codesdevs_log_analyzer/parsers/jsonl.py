"""JSON Lines (JSONL) structured log parser."""

import json
from datetime import datetime
from typing import Any, ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import BaseLogParser
from codesdevs_log_analyzer.utils.time_utils import parse_timestamp


class JSONLParser(BaseLogParser):
    """
    Parser for JSON Lines (JSONL) structured logs.

    Each line is a valid JSON object. Common field names are auto-detected
    for timestamp, level, and message extraction.

    Handles various structured logging formats including:
    - Bunyan (Node.js)
    - Winston
    - Logstash
    - Pino
    - Python structlog
    """

    name: ClassVar[str] = "jsonl"
    description: ClassVar[str] = "JSON Lines structured log format"
    patterns: ClassVar[list[str]] = [
        r"^\s*\{.*\}\s*$",
    ]

    # Common field name mappings
    TIMESTAMP_FIELDS = [
        "timestamp",
        "time",
        "ts",
        "@timestamp",
        "datetime",
        "date",
        "t",
        "created",
        "logged_at",
        "event_time",
        "log_time",
    ]

    LEVEL_FIELDS = [
        "level",
        "severity",
        "log_level",
        "loglevel",
        "lvl",
        "priority",
        "sev",
        "levelname",
        "log.level",
    ]

    MESSAGE_FIELDS = [
        "message",
        "msg",
        "text",
        "log",
        "body",
        "event",
        "description",
        "content",
        "data",
    ]

    # Bunyan numeric levels
    BUNYAN_LEVELS = {
        10: LogLevel.TRACE,
        20: LogLevel.DEBUG,
        30: LogLevel.INFO,
        40: LogLevel.WARN,
        50: LogLevel.ERROR,
        60: LogLevel.FATAL,
    }

    def can_parse(self, line: str) -> bool:
        """Check if line is valid JSON."""
        line = line.strip()
        if not line:
            return False

        # Quick checks
        if not line.startswith("{") or not line.endswith("}"):
            return False

        # Validate JSON
        try:
            json.loads(line)
            return True
        except json.JSONDecodeError:
            return False

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse a JSON line."""
        line = line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Extract timestamp
        timestamp = self._extract_timestamp(data)

        # Extract level
        level = self._extract_level(data)

        # Extract message
        message = self._extract_message(data)

        # Build metadata from remaining fields
        metadata = self._build_metadata(data)

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _extract_timestamp(self, data: dict[str, Any]) -> datetime | None:
        """Extract and parse timestamp from JSON data."""
        for field in self.TIMESTAMP_FIELDS:
            value = self._get_nested_value(data, field)
            if value is not None:
                # Handle numeric timestamps (Unix epoch)
                if isinstance(value, int | float):
                    try:
                        # Detect milliseconds vs seconds
                        if value > 1e12:  # Likely milliseconds
                            return datetime.utcfromtimestamp(value / 1000)
                        return datetime.utcfromtimestamp(value)
                    except (OSError, ValueError, OverflowError):
                        continue

                # Handle string timestamps
                if isinstance(value, str):
                    ts = parse_timestamp(value)
                    if ts is not None:
                        return ts

        return None

    def _extract_level(self, data: dict[str, Any]) -> LogLevel | None:
        """Extract and normalize log level from JSON data."""
        for field in self.LEVEL_FIELDS:
            value = self._get_nested_value(data, field)
            if value is not None:
                # Handle Bunyan numeric levels
                if isinstance(value, int):
                    if value in self.BUNYAN_LEVELS:
                        return self.BUNYAN_LEVELS[value]
                    # Approximate mapping for other numeric levels
                    if value <= 10:
                        return LogLevel.TRACE
                    if value <= 20:
                        return LogLevel.DEBUG
                    if value <= 30:
                        return LogLevel.INFO
                    if value <= 40:
                        return LogLevel.WARN
                    if value <= 50:
                        return LogLevel.ERROR
                    return LogLevel.FATAL

                # Handle string levels
                if isinstance(value, str):
                    level = LogLevel.normalize(value)
                    if level is not None:
                        return level

        return None

    def _extract_message(self, data: dict[str, Any]) -> str:
        """Extract message from JSON data."""
        for field in self.MESSAGE_FIELDS:
            value = self._get_nested_value(data, field)
            if value is not None:
                if isinstance(value, str):
                    return value
                # Convert non-string messages
                return str(value)

        # Fallback: stringify entire object
        return json.dumps(data, default=str)

    def _build_metadata(self, data: dict[str, Any]) -> dict[str, Any]:
        """Build metadata from JSON fields (excluding standard fields)."""
        excluded_fields = set(self.TIMESTAMP_FIELDS + self.LEVEL_FIELDS + self.MESSAGE_FIELDS)

        metadata: dict[str, Any] = {}
        for key, value in data.items():
            if key.lower() not in excluded_fields:
                # Flatten nested objects one level
                if isinstance(value, dict):
                    for nested_key, nested_value in value.items():
                        metadata[f"{key}.{nested_key}"] = nested_value
                else:
                    metadata[key] = value

        return metadata

    def _get_nested_value(self, data: dict[str, Any], key: str) -> Any:
        """Get value from dict, supporting dot notation for nested keys."""
        # Try direct key first (case-insensitive)
        for k, v in data.items():
            if k.lower() == key.lower():
                return v

        # Try nested access
        if "." in key:
            parts = key.split(".")
            current = data
            for part in parts:
                if isinstance(current, dict):
                    # Case-insensitive nested lookup
                    found = False
                    for k, v in current.items():
                        if k.lower() == part.lower():
                            current = v
                            found = True
                            break
                    if not found:
                        return None
                else:
                    return None
            return current

        return None
