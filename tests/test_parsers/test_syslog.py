"""Tests for syslog parser."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.syslog import SyslogParser


class TestSyslogParser:
    """Tests for SyslogParser."""

    @pytest.fixture
    def parser(self) -> SyslogParser:
        """Create parser instance."""
        return SyslogParser(default_year=2026)

    def test_can_parse_valid_line(self, parser: SyslogParser) -> None:
        """Test can_parse returns True for valid syslog lines."""
        assert parser.can_parse("Jan 15 10:30:00 myhost sshd[1234]: Message")
        assert parser.can_parse("Feb  3 08:15:30 server kernel: test")

    def test_can_parse_invalid_line(self, parser: SyslogParser) -> None:
        """Test can_parse returns False for invalid lines."""
        assert not parser.can_parse("2026-01-15 10:30:00 INFO test")
        assert not parser.can_parse("Not a syslog line")
        assert not parser.can_parse("")

    def test_parse_standard_line(self, parser: SyslogParser) -> None:
        """Test parsing standard syslog line."""
        line = "Jan 15 10:30:00 myhost sshd[1234]: Accepted password for user"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.line_number == 1
        assert entry.message == "Accepted password for user"
        assert entry.metadata["hostname"] == "myhost"
        assert entry.metadata["process"] == "sshd"
        assert entry.metadata["pid"] == 1234

    def test_parse_without_pid(self, parser: SyslogParser) -> None:
        """Test parsing line without PID."""
        line = "Jan 15 10:30:00 myhost kernel: test message"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.metadata["process"] == "kernel"
        assert "pid" not in entry.metadata or entry.metadata.get("pid") is None

    def test_parse_timestamp(self, parser: SyslogParser) -> None:
        """Test timestamp extraction."""
        line = "Jan 15 10:30:00 myhost sshd[1234]: test"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.timestamp is not None
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 15
        assert entry.timestamp.hour == 10
        assert entry.timestamp.minute == 30

    def test_level_detection_error(self, parser: SyslogParser) -> None:
        """Test error level detection."""
        line = "Jan 15 10:30:00 myhost app[123]: ERROR: Connection failed"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.ERROR

    def test_level_detection_warning(self, parser: SyslogParser) -> None:
        """Test warning level detection."""
        line = "Jan 15 10:30:00 myhost app[123]: warning: Low disk space"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.WARN

    def test_parse_file(self, parser: SyslogParser, syslog_file: Path) -> None:
        """Test parsing syslog file."""
        entries = list(parser.parse_file(str(syslog_file)))
        assert len(entries) > 0
        assert all(e.timestamp is not None for e in entries)

    def test_detect_confidence(self, sample_syslog_lines: list[str]) -> None:
        """Test format detection confidence."""
        confidence = SyslogParser.detect_confidence(sample_syslog_lines)
        assert confidence > 0.7
