"""Time parsing and formatting utilities for log analysis."""

import re
from datetime import datetime, timedelta, timezone
from typing import Final

from dateutil import parser as dateutil_parser
from dateutil.tz import tzlocal

# ============================================================================
# Common Timestamp Patterns
# ============================================================================

# ISO 8601 variants
ISO_8601_PATTERN: Final[str] = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
ISO_8601_WITH_TZ: Final[str] = (
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})"
)
ISO_8601_WITH_MILLIS: Final[str] = r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]\d{3,9}"

# Syslog format (Jan 15 10:30:00)
SYSLOG_PATTERN: Final[str] = r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"

# Apache/Nginx format [15/Jan/2026:10:30:00 +0000]
APACHE_PATTERN: Final[str] = r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}"

# US format (01/15/2026 10:30:00)
US_DATE_PATTERN: Final[str] = r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}"

# European format (15/01/2026 10:30:00)
EU_DATE_PATTERN: Final[str] = r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}"

# Unix timestamps
UNIX_EPOCH_PATTERN: Final[str] = r"\b1[0-9]{9}\b"  # 10-digit timestamps (seconds)
UNIX_MILLIS_PATTERN: Final[str] = r"\b1[0-9]{12}\b"  # 13-digit timestamps (milliseconds)

# Docker/RFC3339Nano format
RFC3339_NANO_PATTERN: Final[str] = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z"

# Common timestamp patterns for detection (ordered by specificity)
TIMESTAMP_PATTERNS: Final[list[tuple[str, str]]] = [
    (RFC3339_NANO_PATTERN, "RFC3339 Nano"),
    (ISO_8601_WITH_TZ, "ISO 8601 with TZ"),
    (ISO_8601_WITH_MILLIS, "ISO 8601 with milliseconds"),
    (APACHE_PATTERN, "Apache/Nginx"),
    (ISO_8601_PATTERN, "ISO 8601"),
    (SYSLOG_PATTERN, "Syslog"),
    (UNIX_MILLIS_PATTERN, "Unix milliseconds"),
    (UNIX_EPOCH_PATTERN, "Unix epoch"),
    (US_DATE_PATTERN, "US date format"),
]

# Compiled regex patterns for efficiency
_COMPILED_PATTERNS: dict[str, re.Pattern[str]] = {}


def _get_compiled_pattern(pattern: str) -> re.Pattern[str]:
    """Get or compile a regex pattern."""
    if pattern not in _COMPILED_PATTERNS:
        _COMPILED_PATTERNS[pattern] = re.compile(pattern)
    return _COMPILED_PATTERNS[pattern]


# ============================================================================
# Timestamp Parsing
# ============================================================================


def parse_timestamp(
    value: str,
    default_year: int | None = None,
    fuzzy: bool = True,
) -> datetime | None:
    """
    Parse various timestamp formats to datetime.

    Handles:
    - ISO 8601 formats (with/without timezone, milliseconds, nanoseconds)
    - Syslog format (Jan 15 10:30:00)
    - Apache format [15/Jan/2026:10:30:00 +0000]
    - US format (01/15/2026 10:30:00)
    - Unix epoch (seconds and milliseconds)
    - RFC3339Nano for Docker logs

    Args:
        value: The timestamp string to parse
        default_year: Year to use if not present in timestamp (e.g., syslog)
        fuzzy: Whether to use fuzzy parsing for embedded timestamps

    Returns:
        Parsed datetime or None if parsing fails
    """
    if not value or not value.strip():
        return None

    value = value.strip()

    # Try Unix epoch first (fastest check)
    unix_result = _try_parse_unix_epoch(value)
    if unix_result is not None:
        return unix_result

    # Try Apache/Nginx format (specific pattern)
    apache_result = _try_parse_apache_timestamp(value)
    if apache_result is not None:
        return apache_result

    # Try RFC3339Nano (Docker logs)
    rfc3339_result = _try_parse_rfc3339_nano(value)
    if rfc3339_result is not None:
        return rfc3339_result

    # Try syslog format (needs year inference)
    syslog_result = _try_parse_syslog_timestamp(value, default_year)
    if syslog_result is not None:
        return syslog_result

    # Use dateutil for general parsing
    try:
        parsed: datetime = dateutil_parser.parse(value, fuzzy=fuzzy)
        return parsed
    except (ValueError, TypeError, OverflowError):
        pass

    return None


def _try_parse_unix_epoch(value: str) -> datetime | None:
    """Try to parse Unix epoch timestamp."""
    # Check for pure numeric timestamps
    if value.isdigit():
        ts = int(value)
        try:
            # 13 digits = milliseconds
            if len(value) == 13:
                return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
            # 10 digits = seconds
            if len(value) == 10:
                return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            pass
    return None


def _try_parse_apache_timestamp(value: str) -> datetime | None:
    """Try to parse Apache/Nginx timestamp format."""
    # Pattern: [15/Jan/2026:10:30:00 +0000] or 15/Jan/2026:10:30:00 +0000
    pattern = _get_compiled_pattern(
        r"(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})"
    )
    match = pattern.search(value)
    if match:
        day, month, year, hour, minute, second, tz_offset = match.groups()
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
        try:
            # Parse timezone offset
            tz_hours = int(tz_offset[:3])
            tz_minutes = int(tz_offset[0] + tz_offset[3:5])
            tz = timezone(timedelta(hours=tz_hours, minutes=tz_minutes))
            return datetime(
                int(year),
                month_map[month],
                int(day),
                int(hour),
                int(minute),
                int(second),
                tzinfo=tz,
            )
        except (KeyError, ValueError):
            pass
    return None


def _try_parse_rfc3339_nano(value: str) -> datetime | None:
    """Try to parse RFC3339Nano timestamp (Docker format)."""
    pattern = _get_compiled_pattern(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{9})Z")
    match = pattern.search(value)
    if match:
        year, month, day, hour, minute, second, nanos = match.groups()
        try:
            # Convert nanoseconds to microseconds (Python datetime max precision)
            micros = int(nanos[:6])
            return datetime(
                int(year),
                int(month),
                int(day),
                int(hour),
                int(minute),
                int(second),
                micros,
                tzinfo=timezone.utc,
            )
        except ValueError:
            pass
    return None


def _try_parse_syslog_timestamp(value: str, default_year: int | None = None) -> datetime | None:
    """Try to parse syslog timestamp format (Jan 15 10:30:00)."""
    pattern = _get_compiled_pattern(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
    match = pattern.search(value)
    if match:
        month_str, day, hour, minute, second = match.groups()
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
        try:
            month = month_map[month_str]
            year = default_year or datetime.now().year
            return datetime(
                year,
                month,
                int(day),
                int(hour),
                int(minute),
                int(second),
                tzinfo=tzlocal(),
            )
        except (KeyError, ValueError):
            pass
    return None


def extract_timestamp_from_line(line: str, default_year: int | None = None) -> datetime | None:
    """
    Extract and parse timestamp from anywhere in a log line.

    Scans the line for common timestamp patterns and returns the first match.

    Args:
        line: Log line to scan
        default_year: Year to use for timestamps without year

    Returns:
        Parsed datetime or None if no timestamp found
    """
    for pattern, _ in TIMESTAMP_PATTERNS:
        compiled = _get_compiled_pattern(pattern)
        match = compiled.search(line)
        if match:
            result = parse_timestamp(match.group(), default_year)
            if result is not None:
                return result
    return None


# ============================================================================
# Timestamp Formatting
# ============================================================================


def format_timestamp(
    dt: datetime | None,
    format_style: str = "iso",
    include_tz: bool = True,
) -> str:
    """
    Format datetime to human-readable string.

    Args:
        dt: Datetime to format
        format_style: Output style - 'iso', 'human', 'compact'
        include_tz: Whether to include timezone info

    Returns:
        Formatted timestamp string or empty string if dt is None
    """
    if dt is None:
        return ""

    if format_style == "iso":
        if include_tz and dt.tzinfo is not None:
            return dt.isoformat()
        return dt.replace(tzinfo=None).isoformat()

    if format_style == "human":
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    if format_style == "compact":
        return dt.strftime("%m/%d %H:%M:%S")

    return dt.isoformat()


def format_time_range(
    start: datetime | None,
    end: datetime | None,
) -> str:
    """
    Format a time range as human-readable string.

    Args:
        start: Start datetime
        end: End datetime

    Returns:
        Human-readable time range string
    """
    if start is None and end is None:
        return "Unknown time range"

    if start is None:
        return f"Until {format_timestamp(end, 'human')}"

    if end is None:
        return f"From {format_timestamp(start, 'human')}"

    duration = end - start

    # Format duration
    total_seconds = int(duration.total_seconds())
    if total_seconds < 60:
        duration_str = f"{total_seconds} seconds"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        duration_str = f"{minutes} minute{'s' if minutes > 1 else ''}"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        duration_str = f"{hours} hour{'s' if hours > 1 else ''}"
    else:
        days = total_seconds // 86400
        duration_str = f"{days} day{'s' if days > 1 else ''}"

    return (
        f"{format_timestamp(start, 'human')} to {format_timestamp(end, 'human')} ({duration_str})"
    )


# ============================================================================
# Relative Time Parsing
# ============================================================================


def parse_relative_time(value: str, reference: datetime | None = None) -> datetime | None:
    """
    Parse relative time expressions to datetime.

    Handles:
    - "1h ago", "2 hours ago"
    - "30m ago", "30 minutes ago"
    - "yesterday", "today"
    - "last week", "last month"
    - "5d ago", "5 days ago"

    Args:
        value: Relative time expression
        reference: Reference datetime (defaults to now)

    Returns:
        Calculated datetime or None if parsing fails
    """
    if reference is None:
        reference = datetime.now(tz=tzlocal())

    value = value.lower().strip()

    # Handle special keywords
    if value == "now":
        return reference

    if value == "today":
        return reference.replace(hour=0, minute=0, second=0, microsecond=0)

    if value == "yesterday":
        return (reference - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

    if value == "last week":
        return reference - timedelta(weeks=1)

    if value == "last month":
        return reference - timedelta(days=30)

    # Parse "X unit ago" patterns
    pattern = _get_compiled_pattern(
        r"(\d+)\s*(s|sec|second|seconds?|m|min|minute|minutes?|h|hr|hour|hours?|d|day|days?|w|week|weeks?)\s*ago"
    )
    match = pattern.match(value)
    if match:
        amount = int(match.group(1))
        unit = match.group(2).lower()

        if unit.startswith("s"):
            return reference - timedelta(seconds=amount)
        if unit.startswith("m") and not unit.startswith("mo"):
            return reference - timedelta(minutes=amount)
        if unit.startswith("h"):
            return reference - timedelta(hours=amount)
        if unit.startswith("d"):
            return reference - timedelta(days=amount)
        if unit.startswith("w"):
            return reference - timedelta(weeks=amount)

    return None


def time_ago(dt: datetime | None, reference: datetime | None = None) -> str:
    """
    Convert datetime to human-readable "time ago" string.

    Args:
        dt: Datetime to convert
        reference: Reference datetime (defaults to now)

    Returns:
        Human-readable relative time string
    """
    if dt is None:
        return "unknown"

    if reference is None:
        reference = datetime.now(tz=dt.tzinfo or tzlocal())

    # Make both timezone-aware or naive
    if dt.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif dt.tzinfo is not None and reference.tzinfo is None:
        dt = dt.replace(tzinfo=None)

    delta = reference - dt
    total_seconds = int(delta.total_seconds())

    if total_seconds < 0:
        return "in the future"

    if total_seconds < 60:
        return f"{total_seconds} second{'s' if total_seconds != 1 else ''} ago"

    minutes = total_seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"

    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"

    days = hours // 24
    if days < 7:
        return f"{days} day{'s' if days != 1 else ''} ago"

    weeks = days // 7
    if weeks < 4:
        return f"{weeks} week{'s' if weeks != 1 else ''} ago"

    months = days // 30
    if months < 12:
        return f"{months} month{'s' if months != 1 else ''} ago"

    years = days // 365
    return f"{years} year{'s' if years != 1 else ''} ago"
