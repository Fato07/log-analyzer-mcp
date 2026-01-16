"""Pattern matcher analyzer - Search for patterns with context."""

import re
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..parsers.base import BaseLogParser, ParsedLogEntry

# Output limits
MAX_MATCHES = 100
MAX_CONTEXT_LINES = 5


@dataclass
class SearchMatch:
    """A single search match with context."""

    line_number: int
    entry: ParsedLogEntry
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)
    highlight_ranges: list[tuple[int, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "line_number": self.line_number,
            "entry": {
                "line_number": self.entry.line_number,
                "timestamp": self.entry.timestamp.isoformat() if self.entry.timestamp else None,
                "level": self.entry.level,
                "message": self.entry.message,
                "raw_line": self.entry.raw_line,
            },
            "context_before": self.context_before,
            "context_after": self.context_after,
            "highlight_ranges": self.highlight_ranges,
        }


@dataclass
class SearchResult:
    """Result of a pattern search."""

    query: str
    total_matches: int = 0
    total_lines_scanned: int = 0
    matches: list[SearchMatch] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "query": self.query,
            "total_matches": self.total_matches,
            "total_lines_scanned": self.total_lines_scanned,
            "matches": [m.to_dict() for m in self.matches],
            "truncated": self.truncated,
        }


class PatternMatcher:
    """
    Pattern search with context support.
    Memory-efficient: uses rolling buffer for context.
    """

    def __init__(
        self,
        pattern: str,
        regex: bool = True,
        case_sensitive: bool = False,
        context_before: int = 2,
        context_after: int = 2,
        max_matches: int = MAX_MATCHES,
        level_filter: list[str] | None = None,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ):
        """
        Initialize pattern matcher.

        Args:
            pattern: Search pattern (regex or plain text)
            regex: Treat pattern as regex
            case_sensitive: Case-sensitive search
            context_before: Lines of context before match
            context_after: Lines of context after match
            max_matches: Maximum matches to return
            level_filter: Filter by log levels (e.g., ['ERROR', 'WARN'])
            time_start: Filter start time
            time_end: Filter end time
        """
        self.pattern_str = pattern
        self.regex = regex
        self.case_sensitive = case_sensitive
        self.context_before = min(context_before, MAX_CONTEXT_LINES)
        self.context_after = min(context_after, MAX_CONTEXT_LINES)
        self.max_matches = min(max_matches, MAX_MATCHES)
        self.level_filter = {level.upper() for level in level_filter} if level_filter else None
        self.time_start = time_start
        self.time_end = time_end

        # Compile pattern
        flags = 0 if case_sensitive else re.IGNORECASE
        if regex:
            try:
                self._pattern = re.compile(pattern, flags)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}") from e
        else:
            # Escape special characters for plain text search
            escaped = re.escape(pattern)
            self._pattern = re.compile(escaped, flags)

        # State
        self._matches: list[SearchMatch] = []
        self._total_matches = 0
        self._total_lines = 0

        # Rolling buffer for context before
        self._context_buffer: deque[str] = deque(maxlen=self.context_before)

        # Pending matches waiting for context_after
        self._pending_matches: list[tuple[SearchMatch, int]] = []  # (match, remaining_after)

    def _passes_level_filter(self, level: str | None) -> bool:
        """Check if entry passes level filter."""
        if self.level_filter is None:
            return True
        if level is None:
            return False
        return level.upper() in self.level_filter

    def _passes_time_filter(self, timestamp: datetime | None) -> bool:
        """Check if entry passes time filter."""
        if timestamp is None:
            # If no timestamp, pass if no time filters are set
            return self.time_start is None and self.time_end is None
        if self.time_start and timestamp < self.time_start:
            return False
        return not (self.time_end and timestamp > self.time_end)

    def _find_highlights(self, text: str) -> list[tuple[int, int]]:
        """Find all match positions in text for highlighting."""
        highlights = []
        for match in self._pattern.finditer(text):
            highlights.append((match.start(), match.end()))
        return highlights

    def _process_pending_matches(self, raw_line: str) -> None:
        """Add context_after to pending matches."""
        still_pending = []
        for match, remaining in self._pending_matches:
            if remaining > 0:
                match.context_after.append(raw_line)
                if remaining > 1:
                    still_pending.append((match, remaining - 1))
            # When remaining reaches 0, the match is complete
        self._pending_matches = still_pending

    def process_entry(self, entry: ParsedLogEntry, raw_line: str | None = None) -> None:
        """
        Process a single log entry.

        Args:
            entry: Parsed log entry
            raw_line: Raw line (uses entry.raw_line if not provided)
        """
        if raw_line is None:
            raw_line = entry.raw_line

        self._total_lines += 1

        # Add context_after to any pending matches
        self._process_pending_matches(raw_line)

        # Check if this line matches
        if self._pattern.search(raw_line):
            self._total_matches += 1

            # Apply filters
            if not self._passes_level_filter(entry.level):
                self._context_buffer.append(raw_line)
                return

            if not self._passes_time_filter(entry.timestamp):
                self._context_buffer.append(raw_line)
                return

            # Check if we've hit the limit
            if len(self._matches) >= self.max_matches:
                self._context_buffer.append(raw_line)
                return

            # Create match with context_before
            highlights = self._find_highlights(raw_line)
            match = SearchMatch(
                line_number=entry.line_number,
                entry=entry,
                context_before=list(self._context_buffer),
                context_after=[],
                highlight_ranges=highlights,
            )

            self._matches.append(match)

            # Add to pending for context_after collection
            if self.context_after > 0:
                self._pending_matches.append((match, self.context_after))

        # Update context buffer
        self._context_buffer.append(raw_line)

    def finalize(self) -> SearchResult:
        """
        Finalize search and return results.

        Returns:
            SearchResult with all matches
        """
        return SearchResult(
            query=self.pattern_str,
            total_matches=self._total_matches,
            total_lines_scanned=self._total_lines,
            matches=self._matches,
            truncated=self._total_matches > len(self._matches),
        )

    def search_file(
        self, parser: BaseLogParser, file_path: str, max_lines: int = 10000
    ) -> SearchResult:
        """
        Search a log file for patterns.

        Args:
            parser: Parser to use for parsing log entries
            file_path: Path to the log file
            max_lines: Maximum lines to process

        Returns:
            SearchResult with all matches
        """
        for entry in parser.parse_file(file_path, max_lines=max_lines):
            self.process_entry(entry)
        return self.finalize()

    def search_raw_file(
        self, file_path: str, max_lines: int = 10000, encoding: str = "utf-8"
    ) -> SearchResult:
        """
        Search a raw file without parsing.

        Args:
            file_path: Path to the file
            max_lines: Maximum lines to process
            encoding: File encoding

        Returns:
            SearchResult with all matches
        """
        try:
            with open(file_path, encoding=encoding, errors="replace") as f:
                for line_number, line in enumerate(f, start=1):
                    if line_number > max_lines:
                        break

                    line = line.rstrip("\n\r")

                    # Create a minimal ParsedLogEntry for raw search
                    entry = ParsedLogEntry(
                        line_number=line_number,
                        raw_line=line,
                        timestamp=None,
                        level=None,
                        message=line,
                        metadata={},
                    )
                    self.process_entry(entry, raw_line=line)
        except Exception:
            pass

        return self.finalize()

    def search_entries(self, entries: Iterator[ParsedLogEntry]) -> SearchResult:
        """
        Search an iterator of entries.

        Args:
            entries: Iterator of parsed log entries

        Returns:
            SearchResult with all matches
        """
        for entry in entries:
            self.process_entry(entry)
        return self.finalize()


def search_pattern(
    parser: BaseLogParser,
    file_path: str,
    pattern: str,
    regex: bool = True,
    case_sensitive: bool = False,
    context_before: int = 2,
    context_after: int = 2,
    max_matches: int = MAX_MATCHES,
    level_filter: list[str] | None = None,
    time_start: datetime | None = None,
    time_end: datetime | None = None,
    max_lines: int = 10000,
) -> SearchResult:
    """
    Convenience function to search for patterns in a log file.

    Args:
        parser: Parser to use for parsing log entries
        file_path: Path to the log file
        pattern: Search pattern (regex or plain text)
        regex: Treat pattern as regex
        case_sensitive: Case-sensitive search
        context_before: Lines of context before match
        context_after: Lines of context after match
        max_matches: Maximum matches to return
        level_filter: Filter by log levels
        time_start: Filter start time
        time_end: Filter end time
        max_lines: Maximum lines to process

    Returns:
        SearchResult with all matches
    """
    matcher = PatternMatcher(
        pattern=pattern,
        regex=regex,
        case_sensitive=case_sensitive,
        context_before=context_before,
        context_after=context_after,
        max_matches=max_matches,
        level_filter=level_filter,
        time_start=time_start,
        time_end=time_end,
    )
    return matcher.search_file(parser, file_path, max_lines=max_lines)
