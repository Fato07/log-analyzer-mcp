"""Tests for summarizer analyzer."""

from datetime import datetime, timedelta

from codesdevs_log_analyzer.analyzers.summarizer import (
    LogSummary,
    Summarizer,
    summarize_log,
)
from codesdevs_log_analyzer.parsers.base import ParsedLogEntry


class TestSummarizer:
    """Tests for Summarizer class."""

    def test_basic_summary(self, sample_log_entries, tmp_path):
        """Test basic log summary generation."""
        # Create a temp file for file_info
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        for entry in sample_log_entries:
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        assert isinstance(result, LogSummary)
        assert result.total_entries == len(sample_log_entries)

    def test_level_distribution(self, sample_log_entries, tmp_path):
        """Test level distribution tracking."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        for entry in sample_log_entries:
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        assert "ERROR" in result.level_distribution
        assert "INFO" in result.level_distribution
        assert result.level_distribution["ERROR"] == 3

    def test_time_range_tracking(self, sample_log_entries, tmp_path):
        """Test time range tracking."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        for entry in sample_log_entries:
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        assert result.time_range.start is not None
        assert result.time_range.end is not None
        assert result.time_range.start <= result.time_range.end

    def test_top_errors_extraction(self, sample_log_entries, tmp_path):
        """Test that top errors are extracted."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        for entry in sample_log_entries:
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        assert len(result.top_errors) > 0

    def test_recommendations_generated(self, sample_log_entries, tmp_path):
        """Test that recommendations are generated."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        for entry in sample_log_entries:
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        # Should have at least one recommendation given the errors
        assert len(result.recommendations) > 0

    def test_summary_to_dict(self, sample_log_entries, tmp_path):
        """Test conversion to dictionary."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        for entry in sample_log_entries:
            summarizer.process_entry(entry)

        result = summarizer.finalize()
        result_dict = result.to_dict()

        assert "file_info" in result_dict
        assert "time_range" in result_dict
        assert "level_distribution" in result_dict
        assert "top_errors" in result_dict
        assert "anomalies" in result_dict
        assert "recommendations" in result_dict

    def test_summarize_file(self, mock_parser, sample_log_file):
        """Test summarizing a file directly."""
        summarizer = Summarizer(file_path=sample_log_file)
        result = summarizer.summarize_file(mock_parser)

        assert isinstance(result, LogSummary)
        assert result.total_entries > 0


class TestAnomalyDetection:
    """Tests for anomaly detection in summarizer."""

    def test_detect_volume_spike(self, tmp_path):
        """Test detection of log volume spikes."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        # Generate entries with a spike
        base_time = datetime(2024, 1, 15, 10, 0, 0)

        # Normal volume: 5 entries per minute for 5 minutes
        for minute in range(5):
            for i in range(5):
                entry = ParsedLogEntry(
                    line_number=minute * 5 + i,
                    raw_line=f"INFO Normal entry {minute}:{i}",
                    timestamp=base_time + timedelta(minutes=minute, seconds=i),
                    level="INFO",
                    message=f"Normal entry {minute}:{i}",
                    metadata={}
                )
                summarizer.process_entry(entry)

        # Spike: 50 entries in minute 6
        spike_time = base_time + timedelta(minutes=6)
        for i in range(50):
            entry = ParsedLogEntry(
                line_number=100 + i,
                raw_line=f"INFO Spike entry {i}",
                timestamp=spike_time + timedelta(seconds=i % 60),
                level="INFO",
                message=f"Spike entry {i}",
                metadata={}
            )
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        # Should detect the spike
        spike_anomalies = [a for a in result.anomalies if a.type == "spike"]
        assert len(spike_anomalies) > 0

    def test_detect_high_error_rate(self, tmp_path):
        """Test detection of high error rate."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file))

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        # Generate 150 entries, ~33% errors (need > 100 entries for anomaly detection)
        for i in range(150):
            level = "ERROR" if i % 3 == 0 else "INFO"
            entry = ParsedLogEntry(
                line_number=i,
                raw_line=f"{level} Entry {i}",
                timestamp=base_time + timedelta(seconds=i),
                level=level,
                message=f"Entry {i}",
                metadata={}
            )
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        # Should detect unusual error level
        level_anomalies = [a for a in result.anomalies if a.type == "unusual_level"]
        assert len(level_anomalies) > 0


class TestSecurityIndicators:
    """Tests for security indicator tracking."""

    def test_auth_failure_detection(self, tmp_path):
        """Test detection of authentication failures."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file), include_security=True)

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        # Generate auth failure entries
        auth_messages = [
            "authentication failed for user admin",
            "login failed: invalid password",
            "access denied to /admin",
            "unauthorized access attempt",
        ]

        for i, msg in enumerate(auth_messages):
            entry = ParsedLogEntry(
                line_number=i,
                raw_line=f"WARN {msg}",
                timestamp=base_time + timedelta(seconds=i),
                level="WARN",
                message=msg,
                metadata={}
            )
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        assert result.security is not None
        assert result.security.failed_auth_attempts == len(auth_messages)


class TestPerformanceMetrics:
    """Tests for performance metrics tracking."""

    def test_response_time_tracking(self, tmp_path):
        """Test tracking of response times."""
        log_file = tmp_path / "test.log"
        log_file.write_text("test content")

        summarizer = Summarizer(file_path=str(log_file), include_performance=True)

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        # Generate entries with response times
        response_times = [100, 200, 1500, 6000, 300, 11000]

        for i, rt in enumerate(response_times):
            entry = ParsedLogEntry(
                line_number=i,
                raw_line=f"INFO Request completed in {rt}ms",
                timestamp=base_time + timedelta(seconds=i),
                level="INFO",
                message=f"Request completed in {rt}ms",
                metadata={"response_time": rt}
            )
            summarizer.process_entry(entry)

        result = summarizer.finalize()

        assert result.performance is not None
        assert result.performance.total_requests == len(response_times)
        assert result.performance.slow_requests_1s == 3  # 1500, 6000, 11000
        assert result.performance.slow_requests_5s == 2  # 6000, 11000
        assert result.performance.slow_requests_10s == 1  # 11000


class TestSummarizeLogFunction:
    """Tests for summarize_log convenience function."""

    def test_summarize_log_basic(self, mock_parser, sample_log_file):
        """Test basic log summarization."""
        result = summarize_log(mock_parser, sample_log_file)

        assert isinstance(result, LogSummary)
        assert result.total_entries > 0

    def test_summarize_log_no_performance(self, mock_parser, sample_log_file):
        """Test summarization without performance metrics."""
        result = summarize_log(
            mock_parser,
            sample_log_file,
            include_performance=False
        )

        assert result.performance is None

    def test_summarize_log_no_security(self, mock_parser, sample_log_file):
        """Test summarization without security indicators."""
        result = summarize_log(
            mock_parser,
            sample_log_file,
            include_security=False
        )

        assert result.security is None
