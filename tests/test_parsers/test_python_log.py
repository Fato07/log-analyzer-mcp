"""Tests for Python log parser."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.python_log import PythonLogParser


class TestPythonLogParser:
    """Tests for PythonLogParser."""

    @pytest.fixture
    def parser(self) -> PythonLogParser:
        """Create parser instance."""
        return PythonLogParser()

    def test_can_parse_default_format(self, parser: PythonLogParser) -> None:
        """Test can_parse returns True for default format."""
        line = "2026-01-15 10:30:00,123 - myapp.main - INFO - Message"
        assert parser.can_parse(line)

    def test_can_parse_basic_format(self, parser: PythonLogParser) -> None:
        """Test can_parse returns True for basic format."""
        line = "ERROR:myapp.module:Error message"
        assert parser.can_parse(line)

    def test_can_parse_bracket_format(self, parser: PythonLogParser) -> None:
        """Test can_parse returns True for bracket format."""
        line = "[2026-01-15 10:30:00] ERROR myapp: Message"
        assert parser.can_parse(line)

    def test_can_parse_invalid_line(self, parser: PythonLogParser) -> None:
        """Test can_parse returns False for invalid lines."""
        assert not parser.can_parse("Jan 15 10:30:00 syslog")
        assert not parser.can_parse("Not a log line")

    def test_parse_default_format(self, parser: PythonLogParser) -> None:
        """Test parsing default Python logging format."""
        line = "2026-01-15 10:30:00,123 - myapp.main - INFO - Application started"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Application started"
        assert entry.level == LogLevel.INFO
        assert entry.metadata["module"] == "myapp.main"
        assert entry.timestamp is not None

    def test_parse_basic_format(self, parser: PythonLogParser) -> None:
        """Test parsing basic logging format."""
        line = "ERROR:myapp.module:Error occurred"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Error occurred"
        assert entry.level == LogLevel.ERROR
        assert entry.metadata["module"] == "myapp.module"

    def test_parse_timestamp(self, parser: PythonLogParser) -> None:
        """Test timestamp extraction."""
        line = "2026-01-15 10:30:00,123 - app - INFO - test"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.timestamp is not None
        assert entry.timestamp.year == 2026
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 15

    def test_is_continuation_traceback(self, parser: PythonLogParser) -> None:
        """Test traceback continuation detection."""
        assert parser.is_continuation("Traceback (most recent call last):")
        assert parser.is_continuation('  File "/app/module.py", line 45, in func')
        assert parser.is_continuation("    result = process(data)")
        assert parser.is_continuation("ValueError: Invalid input")

    def test_is_continuation_normal_line(self, parser: PythonLogParser) -> None:
        """Test normal lines are not continuations."""
        assert not parser.is_continuation("2026-01-15 10:30:00,123 - app - INFO - test")
        assert not parser.is_continuation("ERROR:app:message")

    def test_parse_file(self, parser: PythonLogParser, python_log_file: Path) -> None:
        """Test parsing Python log file."""
        entries = list(parser.parse_file(str(python_log_file)))
        assert len(entries) > 0

    def test_detect_confidence(self, sample_python_lines: list[str]) -> None:
        """Test format detection confidence."""
        confidence = PythonLogParser.detect_confidence(sample_python_lines)
        assert confidence > 0.7
