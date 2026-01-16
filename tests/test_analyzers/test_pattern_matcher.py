"""Tests for pattern_matcher analyzer."""

import pytest
from datetime import datetime

from codesdevs_log_analyzer.analyzers.pattern_matcher import (
    PatternMatcher,
    SearchMatch,
    SearchResult,
    search_pattern,
)
from codesdevs_log_analyzer.parsers.base import ParsedLogEntry


class TestPatternMatcher:
    """Tests for PatternMatcher class."""

    def test_basic_regex_search(self, sample_log_entries):
        """Test basic regex search."""
        matcher = PatternMatcher(pattern=r"ERROR", regex=True)

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        assert result.total_matches == 3  # 3 ERROR entries
        assert len(result.matches) == 3

    def test_plain_text_search(self, sample_log_entries):
        """Test plain text search (not regex)."""
        matcher = PatternMatcher(pattern="database", regex=False)

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        assert result.total_matches == 2  # "database" appears in 2 entries

    def test_case_insensitive_search(self, sample_log_entries):
        """Test case-insensitive search."""
        matcher = PatternMatcher(
            pattern="error",
            regex=True,
            case_sensitive=False
        )

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        assert result.total_matches >= 3

    def test_case_sensitive_search(self, sample_log_entries):
        """Test case-sensitive search."""
        matcher = PatternMatcher(
            pattern="error",  # lowercase
            regex=True,
            case_sensitive=True
        )

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        # Should not match "ERROR" (uppercase)
        assert result.total_matches == 0

    def test_context_before(self, sample_log_entries):
        """Test context lines before match."""
        matcher = PatternMatcher(
            pattern="ERROR",
            context_before=2,
            context_after=0
        )

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        # First ERROR at line 3 should have 2 context lines before
        if result.matches:
            first_match = result.matches[0]
            assert len(first_match.context_before) <= 2

    def test_context_after(self, sample_log_entries):
        """Test context lines after match."""
        matcher = PatternMatcher(
            pattern="ERROR",
            context_before=0,
            context_after=2
        )

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        # Matches should have context after
        for match in result.matches[:-1]:  # Skip last match
            assert len(match.context_after) <= 2

    def test_max_matches_limit(self, sample_log_entries):
        """Test maximum matches limit."""
        matcher = PatternMatcher(
            pattern=".*",  # Match everything
            max_matches=2
        )

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        assert len(result.matches) == 2
        assert result.truncated is True

    def test_level_filter(self, sample_log_entries):
        """Test filtering by log level."""
        matcher = PatternMatcher(
            pattern=".*",
            level_filter=["ERROR"]
        )

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        # Should only include ERROR level entries
        for match in result.matches:
            assert match.entry.level == "ERROR"

    def test_time_filter(self, sample_log_entries):
        """Test filtering by time range."""
        start_time = datetime(2024, 1, 15, 10, 0, 5)
        end_time = datetime(2024, 1, 15, 10, 0, 15)

        matcher = PatternMatcher(
            pattern=".*",
            time_start=start_time,
            time_end=end_time
        )

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        # All matches should be within time range
        for match in result.matches:
            if match.entry.timestamp:
                assert start_time <= match.entry.timestamp <= end_time

    def test_highlight_ranges(self, sample_log_entries):
        """Test highlight ranges in matches."""
        matcher = PatternMatcher(pattern="ERROR")

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()

        # All matches should have highlight ranges
        for match in result.matches:
            assert len(match.highlight_ranges) > 0

    def test_result_to_dict(self, sample_log_entries):
        """Test conversion to dictionary."""
        matcher = PatternMatcher(pattern="ERROR")

        for entry in sample_log_entries:
            matcher.process_entry(entry)

        result = matcher.finalize()
        result_dict = result.to_dict()

        assert "query" in result_dict
        assert "total_matches" in result_dict
        assert "matches" in result_dict

    def test_invalid_regex(self):
        """Test handling of invalid regex pattern."""
        with pytest.raises(ValueError, match="Invalid regex"):
            PatternMatcher(pattern="[invalid", regex=True)

    def test_search_file(self, mock_parser, sample_log_file):
        """Test searching a file directly."""
        matcher = PatternMatcher(pattern="ERROR")
        result = matcher.search_file(mock_parser, sample_log_file)

        assert isinstance(result, SearchResult)
        assert result.total_matches > 0

    def test_search_raw_file(self, sample_log_file):
        """Test searching a raw file without parsing."""
        matcher = PatternMatcher(pattern="ERROR")
        result = matcher.search_raw_file(sample_log_file)

        assert isinstance(result, SearchResult)
        assert result.total_matches > 0


class TestSearchPatternFunction:
    """Tests for search_pattern convenience function."""

    def test_search_pattern_basic(self, mock_parser, sample_log_file):
        """Test basic pattern search."""
        result = search_pattern(
            mock_parser,
            sample_log_file,
            pattern="ERROR"
        )

        assert isinstance(result, SearchResult)
        assert result.total_matches > 0

    def test_search_pattern_with_options(self, mock_parser, sample_log_file):
        """Test pattern search with various options."""
        result = search_pattern(
            mock_parser,
            sample_log_file,
            pattern="error",
            case_sensitive=False,
            context_before=1,
            context_after=1,
            max_matches=5
        )

        assert isinstance(result, SearchResult)
        assert len(result.matches) <= 5


class TestSearchMatch:
    """Tests for SearchMatch dataclass."""

    def test_match_to_dict(self):
        """Test SearchMatch to_dict method."""
        entry = ParsedLogEntry(
            line_number=10,
            raw_line="2024-01-15 10:00:00 ERROR Test message",
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
            level="ERROR",
            message="Test message",
            metadata={}
        )

        match = SearchMatch(
            line_number=10,
            entry=entry,
            context_before=["line before"],
            context_after=["line after"],
            highlight_ranges=[(0, 5)]
        )

        result = match.to_dict()

        assert result["line_number"] == 10
        assert result["context_before"] == ["line before"]
        assert result["context_after"] == ["line after"]
        assert result["highlight_ranges"] == [(0, 5)]
