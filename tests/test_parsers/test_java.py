"""Tests for Java log parser."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.java import JavaLogParser


class TestJavaLogParser:
    """Tests for JavaLogParser."""

    @pytest.fixture
    def parser(self) -> JavaLogParser:
        """Create parser instance."""
        return JavaLogParser()

    def test_can_parse_log4j_format(self, parser: JavaLogParser) -> None:
        """Test can_parse returns True for Log4j format."""
        line = "2026-01-15 10:30:00,123 INFO  [main] com.example.App - Message"
        assert parser.can_parse(line)

    def test_can_parse_logback_format(self, parser: JavaLogParser) -> None:
        """Test can_parse returns True for Logback format."""
        line = "2026-01-15 10:30:00.123 [main] INFO  com.example.App - Message"
        assert parser.can_parse(line)

    def test_can_parse_invalid_line(self, parser: JavaLogParser) -> None:
        """Test can_parse returns False for invalid lines."""
        assert not parser.can_parse("Jan 15 10:30:00 syslog")
        assert not parser.can_parse("Not a log line")

    def test_parse_log4j_format(self, parser: JavaLogParser) -> None:
        """Test parsing Log4j format."""
        line = "2026-01-15 10:30:00,123 ERROR [main] com.example.Service - Error occurred"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Error occurred"
        assert entry.level == LogLevel.ERROR
        assert entry.metadata["thread"] == "main"
        assert entry.metadata["logger"] == "com.example.Service"

    def test_parse_logback_format(self, parser: JavaLogParser) -> None:
        """Test parsing Logback format."""
        line = "2026-01-15 10:30:00.123 [pool-1-thread-1] WARN  c.e.Cache - Cache miss"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.WARN
        assert entry.metadata["thread"] == "pool-1-thread-1"

    def test_parse_timestamp(self, parser: JavaLogParser) -> None:
        """Test timestamp extraction."""
        line = "2026-01-15 10:30:00,123 INFO [main] App - test"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.timestamp is not None
        assert entry.timestamp.year == 2026

    def test_is_continuation_stack_frame(self, parser: JavaLogParser) -> None:
        """Test stack frame continuation detection."""
        assert parser.is_continuation("\tat com.example.Class.method(File.java:123)")
        assert parser.is_continuation("        at com.example.Class.method(File.java:123)")
        assert parser.is_continuation("Caused by: java.lang.Exception: message")
        assert parser.is_continuation("\t... 10 more")

    def test_is_continuation_normal_line(self, parser: JavaLogParser) -> None:
        """Test normal lines are not continuations."""
        assert not parser.is_continuation("2026-01-15 10:30:00,123 INFO [main] App - test")

    def test_parse_file(self, parser: JavaLogParser, java_log_file: Path) -> None:
        """Test parsing Java log file."""
        entries = list(parser.parse_file(str(java_log_file)))
        assert len(entries) > 0

    def test_detect_confidence(self, sample_java_lines: list[str]) -> None:
        """Test format detection confidence."""
        confidence = JavaLogParser.detect_confidence(sample_java_lines)
        assert confidence > 0.7
