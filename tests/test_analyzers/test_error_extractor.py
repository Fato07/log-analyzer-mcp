"""Tests for error_extractor analyzer."""

from datetime import datetime

from codesdevs_log_analyzer.analyzers.error_extractor import (
    ErrorExtractionResult,
    ErrorExtractor,
    ErrorGroup,
    extract_errors,
    normalize_error_message,
)
from codesdevs_log_analyzer.parsers.base import ParsedLogEntry


class TestNormalizeErrorMessage:
    """Tests for normalize_error_message function."""

    def test_normalize_uuid(self):
        """Test UUID normalization."""
        msg = "Failed to find user 550e8400-e29b-41d4-a716-446655440000"
        result = normalize_error_message(msg)
        assert "<UUID>" in result
        assert "550e8400" not in result

    def test_normalize_ip_address(self):
        """Test IP address normalization."""
        msg = "Connection refused from 192.168.1.100"
        result = normalize_error_message(msg)
        assert "<IP>" in result
        assert "192.168.1.100" not in result

    def test_normalize_timestamp(self):
        """Test timestamp normalization."""
        msg = "Error at 2024-01-15T10:30:00Z: Something failed"
        result = normalize_error_message(msg)
        assert "<TIME>" in result
        assert "2024-01-15" not in result

    def test_normalize_file_path(self):
        """Test file path normalization."""
        msg = "Error in /var/log/app/error.log"
        result = normalize_error_message(msg)
        assert "<PATH>" in result
        assert "/var/log" not in result

    def test_normalize_numbers(self):
        """Test number normalization."""
        msg = "Processed 12345 records in batch 67"
        result = normalize_error_message(msg)
        assert "<N>" in result
        assert "12345" not in result

    def test_preserve_error_codes(self):
        """Test that common error codes are preserved."""
        msg = "HTTP 404 Not Found"
        result = normalize_error_message(msg)
        # Error codes like 404 should be preserved
        assert "404" in result

    def test_normalize_hex_values(self):
        """Test hex value normalization."""
        msg = "Memory error at 0x7fff5fbff8c0"
        result = normalize_error_message(msg)
        assert "<HEX>" in result
        assert "0x7fff" not in result


class TestErrorGroup:
    """Tests for ErrorGroup dataclass."""

    def test_add_entry(self):
        """Test adding entries to error group."""
        group = ErrorGroup(template="Test error")
        entry = ParsedLogEntry(
            line_number=1,
            raw_line="ERROR Test error",
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
            level="ERROR",
            message="Test error",
            metadata={}
        )

        group.add_entry(entry)

        assert group.count == 1
        assert group.first_seen == entry.timestamp
        assert group.last_seen == entry.timestamp
        assert len(group.sample_entries) == 1

    def test_add_multiple_entries(self):
        """Test adding multiple entries updates time range."""
        group = ErrorGroup(template="Test error")

        entry1 = ParsedLogEntry(
            line_number=1,
            raw_line="ERROR Test error",
            timestamp=datetime(2024, 1, 15, 10, 0, 0),
            level="ERROR",
            message="Test error",
            metadata={}
        )
        entry2 = ParsedLogEntry(
            line_number=2,
            raw_line="ERROR Test error",
            timestamp=datetime(2024, 1, 15, 10, 5, 0),
            level="ERROR",
            message="Test error",
            metadata={}
        )

        group.add_entry(entry1)
        group.add_entry(entry2)

        assert group.count == 2
        assert group.first_seen == entry1.timestamp
        assert group.last_seen == entry2.timestamp

    def test_sample_entries_limit(self):
        """Test that sample entries are limited."""
        group = ErrorGroup(template="Test error")

        for i in range(10):
            entry = ParsedLogEntry(
                line_number=i,
                raw_line=f"ERROR Test error {i}",
                timestamp=datetime(2024, 1, 15, 10, i, 0),
                level="ERROR",
                message=f"Test error {i}",
                metadata={}
            )
            group.add_entry(entry)

        # Should only keep first 3 samples
        assert len(group.sample_entries) == 3
        assert group.count == 10


class TestErrorExtractor:
    """Tests for ErrorExtractor class."""

    def test_extract_errors_from_entries(self, sample_log_entries):
        """Test extracting errors from log entries."""
        extractor = ErrorExtractor(include_warnings=True)

        for entry in sample_log_entries:
            extractor.process_entry(entry)

        result = extractor.finalize()

        assert result.total_errors == 3  # 3 ERROR entries
        assert result.total_warnings == 1  # 1 WARN entry
        assert result.unique_errors > 0

    def test_group_similar_errors(self, sample_log_entries):
        """Test that similar errors are grouped."""
        extractor = ErrorExtractor(include_warnings=False, group_similar=True)

        for entry in sample_log_entries:
            extractor.process_entry(entry)

        result = extractor.finalize()

        # "Failed to connect to database" appears twice, should be grouped
        connection_errors = [g for g in result.error_groups if "database" in g.template.lower()]
        assert len(connection_errors) == 1
        assert connection_errors[0].count == 2

    def test_no_grouping(self, sample_log_entries):
        """Test extraction without grouping."""
        extractor = ErrorExtractor(include_warnings=False, group_similar=False)

        for entry in sample_log_entries:
            extractor.process_entry(entry)

        result = extractor.finalize()

        # Without grouping, each unique message is separate
        assert result.unique_errors >= 2

    def test_time_range_tracking(self, sample_log_entries):
        """Test that time range is tracked correctly."""
        extractor = ErrorExtractor()

        for entry in sample_log_entries:
            extractor.process_entry(entry)

        result = extractor.finalize()

        assert result.time_range[0] is not None
        assert result.time_range[1] is not None
        assert result.time_range[0] <= result.time_range[1]

    def test_result_to_dict(self, sample_log_entries):
        """Test conversion to dictionary."""
        extractor = ErrorExtractor()

        for entry in sample_log_entries:
            extractor.process_entry(entry)

        result = extractor.finalize()
        result_dict = result.to_dict()

        assert "total_errors" in result_dict
        assert "total_warnings" in result_dict
        assert "error_groups" in result_dict
        assert "time_range" in result_dict

    def test_analyze_file(self, mock_parser, sample_log_file):
        """Test analyzing a file directly."""
        extractor = ErrorExtractor()
        result = extractor.analyze_file(mock_parser, sample_log_file)

        assert result.total_errors > 0
        assert isinstance(result, ErrorExtractionResult)


class TestExtractErrorsFunction:
    """Tests for extract_errors convenience function."""

    def test_extract_errors_basic(self, mock_parser, sample_log_file):
        """Test basic error extraction."""
        result = extract_errors(mock_parser, sample_log_file)

        assert isinstance(result, ErrorExtractionResult)
        assert result.total_errors > 0

    def test_extract_errors_no_warnings(self, mock_parser, sample_log_file):
        """Test extraction excluding warnings."""
        result = extract_errors(
            mock_parser,
            sample_log_file,
            include_warnings=False
        )

        assert result.total_warnings == 0
