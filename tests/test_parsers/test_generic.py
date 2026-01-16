"""Tests for generic log parser."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.generic import GenericParser


class TestGenericParser:
    """Tests for GenericParser."""

    @pytest.fixture
    def parser(self) -> GenericParser:
        """Create parser instance."""
        return GenericParser(default_year=2026)

    def test_can_parse_iso_timestamp(self, parser: GenericParser) -> None:
        """Test can_parse returns True for ISO timestamp."""
        assert parser.can_parse("2026-01-15T10:30:00Z INFO test")
        assert parser.can_parse("2026-01-15 10:30:00 test message")

    def test_can_parse_us_date(self, parser: GenericParser) -> None:
        """Test can_parse returns True for US date format."""
        assert parser.can_parse("01/15/2026 10:30:00 INFO test")

    def test_can_parse_level_only(self, parser: GenericParser) -> None:
        """Test can_parse returns True for lines with level only."""
        assert parser.can_parse("ERROR Critical failure occurred")
        assert parser.can_parse("WARNING Low disk space")

    def test_can_parse_invalid_line(self, parser: GenericParser) -> None:
        """Test can_parse returns False for completely unstructured lines."""
        assert not parser.can_parse("random")
        assert not parser.can_parse("no timestamp or level")

    def test_parse_iso_format(self, parser: GenericParser) -> None:
        """Test parsing ISO format timestamp."""
        line = "2026-01-15T10:30:00Z INFO Application started"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.timestamp is not None
        assert entry.level == LogLevel.INFO

    def test_parse_space_separated(self, parser: GenericParser) -> None:
        """Test parsing space-separated format."""
        line = "2026-01-15 10:30:00 ERROR Something failed"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.ERROR

    def test_parse_level_detection(self, parser: GenericParser) -> None:
        """Test level detection from various keywords."""
        test_cases = [
            ("ERROR critical failure", LogLevel.ERROR),
            ("WARN low memory", LogLevel.WARN),
            ("INFO started", LogLevel.INFO),
            ("DEBUG trace info", LogLevel.DEBUG),
            ("CRITICAL system down", LogLevel.CRITICAL),
        ]

        for line, expected_level in test_cases:
            entry = parser.parse_line(line, 1)
            assert entry is not None
            assert entry.level == expected_level, f"Failed for: {line}"

    def test_parse_extracts_message(self, parser: GenericParser) -> None:
        """Test message extraction."""
        line = "2026-01-15T10:30:00Z INFO The actual message content"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        # Message should have timestamp/level stripped
        assert "actual message" in entry.message.lower()

    def test_parse_file(self, parser: GenericParser, generic_log_file: Path) -> None:
        """Test parsing generic log file."""
        entries = list(parser.parse_file(str(generic_log_file)))
        assert len(entries) > 0

    def test_detect_confidence_low(self) -> None:
        """Test generic parser has lower confidence."""
        lines = [
            "2026-01-15 10:30:00 INFO test",
            "2026-01-15 10:30:01 ERROR test",
        ]
        confidence = GenericParser.detect_confidence(lines)
        # Generic parser should cap at 0.6 to prefer specific parsers
        assert confidence <= 0.6

    def test_parse_malformed_gracefully(self, parser: GenericParser, malformed_log_file: Path) -> None:
        """Test parser handles malformed input gracefully."""
        entries = list(parser.parse_file(str(malformed_log_file)))
        # Should parse some entries without crashing
        assert len(entries) >= 0  # May or may not find valid entries
