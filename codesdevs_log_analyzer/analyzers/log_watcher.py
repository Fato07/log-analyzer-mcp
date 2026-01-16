"""Log watcher analyzer - Watch log files for new entries using position tracking."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from ..models import ParsedLogEntry
from ..parsers.base import BaseLogParser


@dataclass
class WatchResult:
    """Result of watching a log file for new entries."""

    new_entries: list[ParsedLogEntry] = field(default_factory=list)
    lines_read: int = 0
    current_position: int = 0  # File position for next call
    file_size: int = 0
    has_more: bool = False  # True if more lines available (hit max_lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "new_entries": [
                {
                    "line_number": e.line_number,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "level": e.level.value if e.level else None,
                    "message": e.message[:500],  # Truncate long messages
                    "metadata": e.metadata,
                }
                for e in self.new_entries
            ],
            "lines_read": self.lines_read,
            "current_position": self.current_position,
            "file_size": self.file_size,
            "has_more": self.has_more,
        }


class LogWatcher:
    """
    Stateless log watcher using file position tracking.

    This allows watching a log file for new entries by tracking the file position.
    Each call returns new lines since the last position, enabling a polling-based
    watch mechanism suitable for MCP's request/response model.

    Usage:
        watcher = LogWatcher()

        # First call - get current end position
        result = watcher.watch(file_path, parser, from_position=0)
        # result.current_position = end of file

        # Later calls - get new entries since last position
        result = watcher.watch(file_path, parser, from_position=last_position)
        # result.new_entries contains any new log entries
    """

    # Error level patterns
    ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL", "EMERGENCY", "ERR", "SEVERE", "CRIT"}
    WARNING_LEVELS = {"WARN", "WARNING", "WRN"}

    def watch(
        self,
        file_path: str,
        parser: BaseLogParser,
        from_position: int = 0,
        max_lines: int = 100,
        level_filter: str | None = None,
        pattern_filter: str | None = None,
    ) -> WatchResult:
        """
        Read new lines from a log file since the given position.

        Args:
            file_path: Path to the log file
            parser: Log parser to use for parsing entries
            from_position: File position to start reading from.
                          Use 0 to start from end of file (initial call).
                          Use returned current_position for subsequent calls.
            max_lines: Maximum number of lines to read per call
            level_filter: Optional log level filter (e.g., "ERROR", "WARN,ERROR")
            pattern_filter: Optional regex pattern to filter messages

        Returns:
            WatchResult with new entries and updated position
        """
        result = WatchResult()

        # Get file info
        file_size = os.path.getsize(file_path)
        result.file_size = file_size

        # If from_position is 0, return current end position (initial call)
        if from_position == 0:
            result.current_position = file_size
            return result

        # If from_position >= file_size, no new content
        if from_position >= file_size:
            result.current_position = file_size
            return result

        # Parse level filter
        level_set: set[str] | None = None
        if level_filter:
            level_set = {lvl.strip().upper() for lvl in level_filter.split(",")}

        # Compile pattern filter
        pattern_regex: re.Pattern[str] | None = None
        if pattern_filter:
            try:
                pattern_regex = re.compile(pattern_filter, re.IGNORECASE)
            except re.error:
                # Invalid regex, treat as literal string
                pattern_regex = re.compile(re.escape(pattern_filter), re.IGNORECASE)

        # Read new lines from position
        lines_processed = 0
        with open(file_path, encoding="utf-8", errors="replace") as f:
            f.seek(from_position)

            # Track line numbers (approximate based on position)
            # We can't know exact line numbers without reading from start
            line_number = 0  # Will be updated as we read

            # Use readline() instead of for loop to allow tell() after reading
            while True:
                line = f.readline()
                if not line:  # EOF
                    break

                lines_processed += 1

                # Check if we've read enough lines
                if lines_processed > max_lines:
                    result.has_more = True
                    break

                line_number += 1
                line = line.rstrip("\n\r")

                if not line:
                    continue

                # Parse the line
                entry = parser.parse_line(line, line_number)
                if entry is None:
                    continue

                # Apply level filter
                if level_set:
                    entry_level = entry.level.value.upper() if entry.level else ""
                    if entry_level not in level_set:
                        continue

                # Apply pattern filter
                if pattern_regex and not pattern_regex.search(entry.message):
                    continue

                result.new_entries.append(entry)

            # Update position to current file position
            result.current_position = f.tell()

        result.lines_read = lines_processed
        return result

    def watch_for_errors(
        self,
        file_path: str,
        parser: BaseLogParser,
        from_position: int = 0,
        max_lines: int = 100,
        include_warnings: bool = False,
    ) -> WatchResult:
        """
        Convenience method to watch for errors (and optionally warnings).

        Args:
            file_path: Path to the log file
            parser: Log parser to use
            from_position: File position to start reading from
            max_lines: Maximum number of lines to read
            include_warnings: If True, also include WARN level entries

        Returns:
            WatchResult with error (and warning) entries
        """
        levels = list(self.ERROR_LEVELS)
        if include_warnings:
            levels.extend(self.WARNING_LEVELS)

        return self.watch(
            file_path=file_path,
            parser=parser,
            from_position=from_position,
            max_lines=max_lines,
            level_filter=",".join(levels),
        )
