"""Tests for log_watcher analyzer."""

import os
import tempfile
from pathlib import Path

import pytest

from codesdevs_log_analyzer.analyzers.log_watcher import (
    LogWatcher,
    WatchResult,
)


class TestWatchResult:
    """Tests for WatchResult dataclass."""

    def test_default_values(self):
        """Test default values are set correctly."""
        result = WatchResult()
        assert result.new_entries == []
        assert result.lines_read == 0
        assert result.current_position == 0
        assert result.file_size == 0
        assert result.has_more is False

    def test_to_dict(self):
        """Test to_dict serialization."""
        result = WatchResult(
            new_entries=[],
            lines_read=10,
            current_position=500,
            file_size=1000,
            has_more=True,
        )
        d = result.to_dict()

        assert d["new_entries"] == []
        assert d["lines_read"] == 10
        assert d["current_position"] == 500
        assert d["file_size"] == 1000
        assert d["has_more"] is True


class TestLogWatcher:
    """Tests for LogWatcher class."""

    def test_initial_call_returns_end_position(self, sample_log_file, mock_parser):
        """Test that from_position=0 returns current end of file."""
        watcher = LogWatcher()
        result = watcher.watch(
            file_path=str(sample_log_file),
            parser=mock_parser,
            from_position=0,
        )

        # Should return end of file position
        assert result.current_position == os.path.getsize(sample_log_file)
        assert result.file_size == os.path.getsize(sample_log_file)
        assert result.new_entries == []
        assert result.lines_read == 0

    def test_read_from_position(self, tmp_path, mock_parser):
        """Test reading new entries from a given position."""
        # Create initial file
        log_file = tmp_path / "growing.log"
        initial_content = "2024-01-15 10:00:00 INFO Initial entry\n"
        log_file.write_text(initial_content)

        watcher = LogWatcher()

        # Get initial position
        result1 = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=0,
        )
        initial_position = result1.current_position

        # Add new entries to file
        with open(log_file, "a") as f:
            f.write("2024-01-15 10:00:01 ERROR New error occurred\n")
            f.write("2024-01-15 10:00:02 INFO Another entry\n")

        # Read from saved position
        result2 = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=initial_position,
        )

        assert len(result2.new_entries) == 2
        assert result2.lines_read == 2
        assert result2.current_position > initial_position

    def test_no_new_entries_when_unchanged(self, sample_log_file, mock_parser):
        """Test that reading from end returns no new entries."""
        watcher = LogWatcher()

        # Get end position
        result1 = watcher.watch(
            file_path=str(sample_log_file),
            parser=mock_parser,
            from_position=0,
        )

        # Read from end - should have no new entries
        result2 = watcher.watch(
            file_path=str(sample_log_file),
            parser=mock_parser,
            from_position=result1.current_position,
        )

        assert result2.new_entries == []
        assert result2.lines_read == 0

    def test_level_filter(self, tmp_path, mock_parser):
        """Test level filtering works correctly."""
        log_file = tmp_path / "mixed.log"
        log_file.write_text(
            "2024-01-15 10:00:00 INFO Info message\n"
            "2024-01-15 10:00:01 ERROR Error message\n"
            "2024-01-15 10:00:02 WARN Warning message\n"
            "2024-01-15 10:00:03 ERROR Another error\n"
        )

        watcher = LogWatcher()
        result = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=1,  # Start from beginning
            level_filter="ERROR",
        )

        # Should only get ERROR entries
        assert all(e.level and e.level.value.upper() == "ERROR" for e in result.new_entries)
        assert len(result.new_entries) == 2

    def test_pattern_filter(self, tmp_path, mock_parser):
        """Test pattern filtering works correctly."""
        # Create file with initial content
        log_file = tmp_path / "pattern.log"
        log_file.write_text("2024-01-15 09:59:59 INFO Initial entry\n")

        watcher = LogWatcher()
        # Get initial position (end of file)
        result0 = watcher.watch(str(log_file), mock_parser, from_position=0)
        start_pos = result0.current_position

        # Now append content
        with open(log_file, "a") as f:
            f.write("2024-01-15 10:00:00 INFO Processing user request-123\n")
            f.write("2024-01-15 10:00:01 INFO Processing system task\n")
            f.write("2024-01-15 10:00:02 ERROR request-456 failed\n")

        result = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=start_pos,
            pattern_filter="request-\\d+",
        )

        # Should only get entries matching pattern
        assert len(result.new_entries) == 2

    def test_max_lines_limit(self, tmp_path, mock_parser):
        """Test that max_lines limits entries returned."""
        # Create file with initial content
        log_file = tmp_path / "many.log"
        log_file.write_text("2024-01-15 09:59:59 INFO Initial entry\n")

        watcher = LogWatcher()
        result0 = watcher.watch(str(log_file), mock_parser, from_position=0)
        start_pos = result0.current_position

        # Write many lines
        with open(log_file, "a") as f:
            for i in range(100):
                f.write(f"2024-01-15 10:00:{i % 60:02d} INFO Message {i}\n")

        result = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=start_pos,
            max_lines=10,
        )

        assert result.has_more is True
        assert result.lines_read == 11  # Read 11, processed up to max

    def test_watch_for_errors(self, tmp_path, mock_parser):
        """Test convenience method for watching errors."""
        log_file = tmp_path / "errors.log"
        log_file.write_text(
            "2024-01-15 10:00:00 INFO Normal message\n"
            "2024-01-15 10:00:01 ERROR Critical failure\n"
            "2024-01-15 10:00:02 WARN Warning sign\n"
            "2024-01-15 10:00:03 FATAL System down\n"
        )

        watcher = LogWatcher()
        result = watcher.watch_for_errors(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=1,
            include_warnings=False,
        )

        # Should only get ERROR and FATAL (and CRITICAL, EMERGENCY, etc.)
        error_levels = {"ERROR", "CRITICAL", "FATAL", "EMERGENCY", "ERR", "SEVERE", "CRIT"}
        for entry in result.new_entries:
            if entry.level:
                assert entry.level.value.upper() in error_levels

    def test_watch_for_errors_with_warnings(self, tmp_path, mock_parser):
        """Test watching errors with warnings included."""
        log_file = tmp_path / "errors.log"
        log_file.write_text(
            "2024-01-15 10:00:00 INFO Normal message\n"
            "2024-01-15 10:00:01 ERROR Critical failure\n"
            "2024-01-15 10:00:02 WARN Warning sign\n"
        )

        watcher = LogWatcher()
        result = watcher.watch_for_errors(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=1,
            include_warnings=True,
        )

        # Should get both ERROR and WARN entries
        levels = {e.level.value.upper() for e in result.new_entries if e.level}
        assert "ERROR" in levels or "WARN" in levels

    def test_multiple_level_filter(self, tmp_path, mock_parser):
        """Test filtering by multiple levels."""
        log_file = tmp_path / "multi.log"
        log_file.write_text(
            "2024-01-15 10:00:00 INFO Info message\n"
            "2024-01-15 10:00:01 ERROR Error message\n"
            "2024-01-15 10:00:02 WARN Warning message\n"
            "2024-01-15 10:00:03 DEBUG Debug message\n"
        )

        watcher = LogWatcher()
        result = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=1,
            level_filter="ERROR,WARN",
        )

        # Should get ERROR and WARN entries
        levels = {e.level.value.upper() for e in result.new_entries if e.level}
        assert levels == {"ERROR", "WARN"} or levels.issubset({"ERROR", "WARN", "WARNING"})

    def test_invalid_regex_pattern_treated_as_literal(self, tmp_path, mock_parser):
        """Test that invalid regex is treated as literal string."""
        log_file = tmp_path / "regex.log"
        log_file.write_text(
            "2024-01-15 10:00:00 INFO Message with [brackets]\n"
            "2024-01-15 10:00:01 INFO Normal message\n"
        )

        watcher = LogWatcher()
        # Invalid regex (unmatched bracket) should be escaped
        result = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=1,
            pattern_filter="[brackets]",
        )

        # Should still work by treating as literal
        assert len(result.new_entries) >= 1

    def test_combined_filters(self, tmp_path, mock_parser):
        """Test combining level and pattern filters."""
        # Create file with initial content
        log_file = tmp_path / "combined.log"
        log_file.write_text("2024-01-15 09:59:59 INFO Initial entry\n")

        watcher = LogWatcher()
        result0 = watcher.watch(str(log_file), mock_parser, from_position=0)
        start_pos = result0.current_position

        # Append content
        with open(log_file, "a") as f:
            f.write("2024-01-15 10:00:00 ERROR Database error on server-1\n")
            f.write("2024-01-15 10:00:01 ERROR Network error on server-2\n")
            f.write("2024-01-15 10:00:02 INFO Database status ok\n")
            f.write("2024-01-15 10:00:03 ERROR CPU error on server-3\n")

        result = watcher.watch(
            file_path=str(log_file),
            parser=mock_parser,
            from_position=start_pos,
            level_filter="ERROR",
            pattern_filter="Database",
        )

        # Should only get ERROR entries containing "Database"
        assert len(result.new_entries) == 1
        assert "Database" in result.new_entries[0].message
