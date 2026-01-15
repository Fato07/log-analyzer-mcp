"""Generic timestamp-based log parser - fallback for any timestamped logs."""

import re
from datetime import datetime
from typing import Optional

from dateutil import parser as date_parser  # type: ignore[import-untyped]

from .base import BaseLogParser, ParsedLogEntry


class GenericParser(BaseLogParser):
    """Fallback parser for any log with recognizable timestamps."""

    name = "generic"
    patterns = [
        # ISO 8601
        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
        # US format
        r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',
        # European format
        r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',
        # Unix epoch
        r'^\d{10,13}\b',
    ]

    # Level keywords to detect
    LEVEL_KEYWORDS = ['ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG', 'TRACE', 'FATAL', 'CRITICAL']
    LEVEL_PATTERN = re.compile(r'\b(' + '|'.join(LEVEL_KEYWORDS) + r')\b', re.IGNORECASE)

    # Timestamp patterns
    TIMESTAMP_PATTERNS = [
        # ISO 8601 with T separator
        re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'),
        # ISO 8601 with space separator
        re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)?)'),
        # US format MM/DD/YYYY
        re.compile(r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})'),
        # European format DD/MM/YYYY
        re.compile(r'(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})'),
        # Unix epoch (10 or 13 digits)
        re.compile(r'^(\d{10,13})\b'),
    ]

    def can_parse(self, line: str) -> bool:
        """Check if this parser can handle the line."""
        if not line.strip():
            return False

        # Try to find any timestamp pattern
        for pattern in self.TIMESTAMP_PATTERNS:
            if pattern.search(line):
                return True

        # Also accept lines with log level keywords
        if self.LEVEL_PATTERN.search(line):
            return True

        return False

    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        """Parse a single log line."""
        if not line.strip():
            return None

        timestamp = self._extract_timestamp(line)
        level = self._extract_level(line)
        message = line  # Keep full line as message for generic parser

        return ParsedLogEntry(
            line_number=line_number,
            raw_line=line,
            timestamp=timestamp,
            level=level,
            message=message,
            metadata={}
        )

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from line."""
        for pattern in self.TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                ts_str = match.group(1)
                try:
                    # Handle Unix epoch
                    if ts_str.isdigit():
                        epoch_int = int(ts_str)
                        # Convert milliseconds to seconds
                        epoch_float: float = float(epoch_int)
                        if epoch_int > 9999999999:
                            epoch_float = epoch_int / 1000
                        return datetime.fromtimestamp(epoch_float)

                    # Use dateutil for flexible parsing
                    parsed: datetime = date_parser.parse(ts_str)
                    return parsed
                except Exception:
                    continue
        return None

    def _extract_level(self, line: str) -> Optional[str]:
        """Extract log level from line."""
        match = self.LEVEL_PATTERN.search(line)
        if match:
            return match.group(1).upper()
        return None
