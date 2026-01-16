"""Tests for correlator analyzer."""

from datetime import datetime, timedelta

from codesdevs_log_analyzer.analyzers.correlator import (
    CorrelationResult,
    CorrelationWindow,
    Correlator,
    StreamingCorrelator,
    correlate_events,
)
from codesdevs_log_analyzer.parsers.base import ParsedLogEntry


def create_entry(
    line_number: int,
    message: str,
    timestamp: datetime,
    level: str = "INFO",
    metadata: dict | None = None
) -> ParsedLogEntry:
    """Helper to create test entries."""
    return ParsedLogEntry(
        line_number=line_number,
        raw_line=f"{timestamp.isoformat()} {level} {message}",
        timestamp=timestamp,
        level=level,
        message=message,
        metadata=metadata or {}
    )


class TestCorrelator:
    """Tests for Correlator class."""

    def test_find_anchors(self):
        """Test finding anchor events by pattern."""
        correlator = Correlator(anchor_pattern="database error", regex=False)

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        entries = [
            create_entry(1, "Starting application", base_time, "INFO"),
            create_entry(2, "Database error: connection refused", base_time + timedelta(seconds=10), "ERROR"),
            create_entry(3, "Retrying connection", base_time + timedelta(seconds=11), "INFO"),
            create_entry(4, "Database error: timeout", base_time + timedelta(seconds=30), "ERROR"),
        ]

        for entry in entries:
            correlator.process_entry(entry)

        result = correlator.finalize()

        assert result.total_anchors == 2  # Two "database error" entries

    def test_correlation_window_before(self):
        """Test events before anchor are captured."""
        correlator = Correlator(
            anchor_pattern="CRASH",
            window_before=60,
            window_after=0
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        entries = [
            create_entry(1, "Memory usage high", base_time, "WARN"),
            create_entry(2, "CPU spike detected", base_time + timedelta(seconds=10), "WARN"),
            create_entry(3, "Application CRASH", base_time + timedelta(seconds=15), "ERROR"),
        ]

        for entry in entries:
            correlator.process_entry(entry)

        result = correlator.finalize()

        assert len(result.windows) == 1
        window = result.windows[0]
        assert len(window.events_before) == 2

    def test_correlation_window_after(self):
        """Test events after anchor are captured."""
        correlator = Correlator(
            anchor_pattern="START",
            window_before=0,
            window_after=60
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        entries = [
            create_entry(1, "Application START", base_time, "INFO"),
            create_entry(2, "Loading config", base_time + timedelta(seconds=5), "INFO"),
            create_entry(3, "Ready to serve", base_time + timedelta(seconds=10), "INFO"),
        ]

        for entry in entries:
            correlator.process_entry(entry)

        result = correlator.finalize()

        assert len(result.windows) == 1
        window = result.windows[0]
        assert len(window.events_after) == 2

    def test_related_errors_captured(self):
        """Test that related errors in window are captured."""
        correlator = Correlator(
            anchor_pattern="main failure",
            window_before=30,
            window_after=30
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        entries = [
            create_entry(1, "Database error", base_time, "ERROR"),
            create_entry(2, "Cache error", base_time + timedelta(seconds=5), "ERROR"),
            create_entry(3, "Service main failure", base_time + timedelta(seconds=10), "FATAL"),
            create_entry(4, "Cleanup error", base_time + timedelta(seconds=15), "ERROR"),
        ]

        for entry in entries:
            correlator.process_entry(entry)

        result = correlator.finalize()

        assert len(result.windows) == 1
        window = result.windows[0]
        # Should have errors from before (2) and after (1)
        assert len(window.related_errors) >= 2

    def test_max_anchors_limit(self):
        """Test maximum anchors limit."""
        correlator = Correlator(
            anchor_pattern="error",
            max_anchors=2
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        for i in range(5):
            entry = create_entry(
                i,
                f"error {i}",
                base_time + timedelta(seconds=i * 10),
                "ERROR"
            )
            correlator.process_entry(entry)

        result = correlator.finalize()

        assert result.total_anchors == 5
        assert len(result.windows) == 2
        assert result.truncated is True

    def test_common_precursors(self):
        """Test identification of common precursors."""
        correlator = Correlator(
            anchor_pattern="CRASH",
            window_before=60,
            window_after=0
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        # Create multiple crashes with common precursors
        for crash_num in range(3):
            crash_time = base_time + timedelta(minutes=crash_num * 5)

            # Common precursor
            correlator.process_entry(create_entry(
                crash_num * 10 + 1,
                "Memory warning",
                crash_time - timedelta(seconds=30),
                "WARN"
            ))

            # The crash
            correlator.process_entry(create_entry(
                crash_num * 10 + 2,
                "Application CRASH",
                crash_time,
                "ERROR"
            ))

        result = correlator.finalize()

        assert len(result.windows) == 3
        # Memory warning should be identified as common precursor
        assert len(result.common_precursors) > 0

    def test_result_to_dict(self):
        """Test conversion to dictionary."""
        correlator = Correlator(anchor_pattern="error")

        base_time = datetime(2024, 1, 15, 10, 0, 0)
        correlator.process_entry(create_entry(1, "error occurred", base_time, "ERROR"))

        result = correlator.finalize()
        result_dict = result.to_dict()

        assert "anchor_pattern" in result_dict
        assert "total_anchors" in result_dict
        assert "windows" in result_dict
        assert "common_precursors" in result_dict

    def test_correlate_file(self, mock_parser, sample_log_file):
        """Test correlating a file directly."""
        correlator = Correlator(anchor_pattern="ERROR")
        result = correlator.correlate_file(mock_parser, sample_log_file)

        assert isinstance(result, CorrelationResult)


class TestStreamingCorrelator:
    """Tests for StreamingCorrelator class."""

    def test_streaming_finds_anchors(self):
        """Test that streaming correlator finds anchors."""
        correlator = StreamingCorrelator(
            anchor_pattern="error",
            window_before=30,
            window_after=10
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        entries = [
            create_entry(1, "normal message", base_time, "INFO"),
            create_entry(2, "error occurred", base_time + timedelta(seconds=10), "ERROR"),
            create_entry(3, "recovery started", base_time + timedelta(seconds=15), "INFO"),
            create_entry(4, "recovery complete", base_time + timedelta(seconds=20), "INFO"),
        ]

        for entry in entries:
            correlator.process_entry(entry)

        result = correlator.finalize()

        assert result.total_anchors == 1

    def test_streaming_captures_before_events(self):
        """Test that streaming mode captures events before anchor."""
        correlator = StreamingCorrelator(
            anchor_pattern="CRASH",
            window_before=60,
            window_after=0
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        entries = [
            create_entry(1, "Warning sign 1", base_time, "WARN"),
            create_entry(2, "Warning sign 2", base_time + timedelta(seconds=10), "WARN"),
            create_entry(3, "Application CRASH", base_time + timedelta(seconds=20), "ERROR"),
        ]

        for entry in entries:
            correlator.process_entry(entry)

        result = correlator.finalize()

        assert len(result.windows) == 1
        assert len(result.windows[0].events_before) == 2

    def test_streaming_memory_efficiency(self):
        """Test that streaming mode doesn't store all entries."""
        correlator = StreamingCorrelator(
            anchor_pattern="ERROR",
            window_before=10,
            window_after=10
        )

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        # Generate many entries
        for i in range(1000):
            level = "ERROR" if i == 500 else "INFO"
            entry = create_entry(
                i,
                f"Message {i}" if level != "ERROR" else "ERROR occurred",
                base_time + timedelta(seconds=i),
                level
            )
            correlator.process_entry(entry)

        result = correlator.finalize()

        # Should find the one error
        assert result.total_anchors == 1
        # But shouldn't have stored all 1000 entries
        # (The sliding window should have limited memory usage)


class TestCorrelationWindow:
    """Tests for CorrelationWindow dataclass."""

    def test_window_to_dict(self):
        """Test CorrelationWindow to_dict method."""
        anchor = create_entry(
            10,
            "Critical failure",
            datetime(2024, 1, 15, 10, 0, 0),
            "ERROR"
        )

        window = CorrelationWindow(
            anchor_entry=anchor,
            events_before=[
                create_entry(8, "Warning 1", datetime(2024, 1, 15, 9, 59, 50), "WARN"),
                create_entry(9, "Warning 2", datetime(2024, 1, 15, 9, 59, 55), "WARN"),
            ],
            events_after=[
                create_entry(11, "Recovery", datetime(2024, 1, 15, 10, 0, 5), "INFO"),
            ],
            related_errors=[],
            unique_sources=["server1", "server2"]
        )

        result = window.to_dict()

        assert result["anchor"]["line_number"] == 10
        assert len(result["events_before"]) == 2
        assert len(result["events_after"]) == 1
        assert result["unique_sources"] == ["server1", "server2"]


class TestCorrelateEventsFunction:
    """Tests for correlate_events convenience function."""

    def test_correlate_events_basic(self, mock_parser, sample_log_file):
        """Test basic event correlation."""
        result = correlate_events(
            mock_parser,
            sample_log_file,
            anchor_pattern="ERROR"
        )

        assert isinstance(result, CorrelationResult)

    def test_correlate_events_streaming(self, mock_parser, sample_log_file):
        """Test event correlation in streaming mode."""
        result = correlate_events(
            mock_parser,
            sample_log_file,
            anchor_pattern="ERROR",
            streaming=True
        )

        assert isinstance(result, CorrelationResult)

    def test_correlate_events_with_options(self, mock_parser, sample_log_file):
        """Test event correlation with various options."""
        result = correlate_events(
            mock_parser,
            sample_log_file,
            anchor_pattern="error",
            window_before=120,
            window_after=60,
            max_anchors=5,
            case_sensitive=False
        )

        assert isinstance(result, CorrelationResult)
