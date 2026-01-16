"""Generic timestamp-based log parser."""

import re
from typing import ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import BaseLogParser
from codesdevs_log_analyzer.utils.time_utils import extract_timestamp_from_line


class GenericParser(BaseLogParser):
    """
    Generic fallback parser for logs with recognizable timestamps.

    Attempts to extract timestamps and log levels from any log format.
    Used as a fallback when no specific parser matches.

    Detects:
    - ISO 8601 timestamps
    - US/European date formats
    - Unix epoch timestamps
    - Common log level keywords (ERROR, WARN, INFO, DEBUG, etc.)
    """

    name: ClassVar[str] = "generic"
    description: ClassVar[str] = "Generic parser with timestamp detection"
    patterns: ClassVar[list[str]] = [
        r"\d{4}-\d{2}-\d{2}",  # ISO date
        r"\d{2}/\d{2}/\d{4}",  # US/EU date
        r"\b1[0-9]{9}\b",  # Unix timestamp
    ]

    # Log level patterns (case-insensitive)
    LEVEL_PATTERNS = [
        (re.compile(r"\b(EMERG|EMERGENCY|PANIC)\b", re.I), LogLevel.EMERGENCY),
        (re.compile(r"\b(CRIT|CRITICAL)\b", re.I), LogLevel.CRITICAL),
        (re.compile(r"\b(FATAL)\b", re.I), LogLevel.FATAL),
        (re.compile(r"\b(ERR|ERROR|SEVERE)\b", re.I), LogLevel.ERROR),
        (re.compile(r"\b(WARN|WARNING|WRN)\b", re.I), LogLevel.WARN),
        (re.compile(r"\b(NOTICE)\b", re.I), LogLevel.NOTICE),
        (re.compile(r"\b(INFO|INF)\b", re.I), LogLevel.INFO),
        (re.compile(r"\b(DEBUG|DBG|TRACE|VERBOSE)\b", re.I), LogLevel.DEBUG),
    ]

    # Timestamp extraction patterns (ordered by specificity)
    TIMESTAMP_PATTERNS = [
        # ISO 8601 with timezone
        re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"),
        # ISO 8601 with space separator
        re.compile(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?)"),
        # Syslog format
        re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
        # US format
        re.compile(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})"),
        # European format with time
        re.compile(r"(\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2})"),
        # Unix timestamp (10 or 13 digits)
        re.compile(r"\b(1[0-9]{9}(?:\d{3})?)\b"),
    ]

    def can_parse(self, line: str) -> bool:
        """
        Check if line has any recognizable timestamp.

        Generic parser accepts almost anything with a timestamp.
        """
        if not line or len(line) < 8:
            return False

        # Check for any timestamp pattern
        for pattern in self.TIMESTAMP_PATTERNS:
            if pattern.search(line):
                return True

        # Check for any log level keyword as fallback
        return any(pattern.search(line) for pattern, _ in self.LEVEL_PATTERNS)

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse a line using generic extraction."""
        if not line:
            return None

        # Extract timestamp
        timestamp = extract_timestamp_from_line(line, self.default_year)

        # Extract log level
        level = self._detect_level(line)

        # Extract message (everything after timestamp/level markers)
        message = self._extract_message(line)

        # Build metadata
        metadata: dict[str, bool | str | None] = {}

        # Try to detect format hints
        if self._looks_like_json(line):
            metadata["format_hint"] = "json"
        elif self._looks_like_csv(line):
            metadata["format_hint"] = "csv"

        # Mark if we found structured data
        if timestamp is not None:
            metadata["timestamp_detected"] = True
        if level is not None:
            metadata["level_detected"] = True

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _detect_level(self, line: str) -> LogLevel | None:
        """
        Detect log level from line content.

        Prioritizes level keywords found at the start of the line
        to avoid matching level words in the message body.
        """
        # First, try to find level at the very beginning of the line
        # This handles cases like "ERROR critical failure" where ERROR is the level
        for pattern, level in self.LEVEL_PATTERNS:
            match = pattern.match(line)
            if match:
                return level

        # Then check for level after common timestamp patterns
        # Look for level that appears early in the line (first 50 chars)
        prefix = line[:50] if len(line) > 50 else line
        for pattern, level in self.LEVEL_PATTERNS:
            if pattern.search(prefix):
                return level

        return None

    def _extract_message(self, line: str) -> str:
        """
        Extract the main message from a log line.

        Tries to strip common prefixes like timestamps and levels.
        """
        message = line

        # Try to find and remove timestamp
        for pattern in self.TIMESTAMP_PATTERNS:
            match = pattern.search(message)
            if match:
                # Remove timestamp and any following separator
                ts_end = match.end()
                remaining = message[ts_end:].lstrip(" -:|\t")
                if remaining:
                    message = remaining
                break

        # Try to find and remove level prefix
        for pattern, _ in self.LEVEL_PATTERNS:
            match = pattern.match(message)
            if match:
                remaining = message[match.end() :].lstrip(" -:|\t")
                if remaining:
                    message = remaining
                break

        return message.strip()

    def _looks_like_json(self, line: str) -> bool:
        """Check if line looks like JSON."""
        stripped = line.strip()
        return (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        )

    def _looks_like_csv(self, line: str) -> bool:
        """Check if line looks like CSV."""
        # Count commas - CSV typically has regular comma-separated fields
        comma_count = line.count(",")
        if comma_count < 2:
            return False

        # Check for quoted fields
        if '","' in line or "','" in line:
            return True

        # Check for regular spacing
        parts = line.split(",")
        return len(parts) >= 3 and all(p.strip() for p in parts[:3])

    @classmethod
    def detect_confidence(cls, sample_lines: list[str]) -> float:
        """
        Return confidence score for generic parser.

        Generic parser should have lower base confidence so specific
        parsers are preferred when they match.
        """
        if not sample_lines:
            return 0.0

        parser = cls()
        matched = 0
        timestamp_found = 0
        level_found = 0

        for line in sample_lines:
            if not line.strip():
                continue

            if parser.can_parse(line):
                matched += 1

            entry = parser.parse_line(line, 0)
            if entry:
                if entry.timestamp:
                    timestamp_found += 1
                if entry.level:
                    level_found += 1

        total = len([line for line in sample_lines if line.strip()])
        if total == 0:
            return 0.0

        # Base score from matching
        base_score = matched / total

        # Bonus for finding timestamps and levels
        timestamp_bonus = (timestamp_found / total) * 0.2
        level_bonus = (level_found / total) * 0.1

        # Cap at 0.6 to prefer specific parsers
        return min(0.6, base_score * 0.5 + timestamp_bonus + level_bonus)
