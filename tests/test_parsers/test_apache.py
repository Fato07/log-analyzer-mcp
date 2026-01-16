"""Tests for Apache/Nginx log parsers."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.apache import ApacheAccessParser, ApacheErrorParser


class TestApacheAccessParser:
    """Tests for ApacheAccessParser."""

    @pytest.fixture
    def parser(self) -> ApacheAccessParser:
        """Create parser instance."""
        return ApacheAccessParser()

    def test_can_parse_valid_line(self, parser: ApacheAccessParser) -> None:
        """Test can_parse returns True for valid access log lines."""
        line = '192.168.1.1 - - [15/Jan/2026:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla"'
        assert parser.can_parse(line)

    def test_can_parse_invalid_line(self, parser: ApacheAccessParser) -> None:
        """Test can_parse returns False for invalid lines."""
        assert not parser.can_parse("Jan 15 10:30:00 syslog line")
        assert not parser.can_parse("Not an access log")
        assert not parser.can_parse("")

    def test_parse_combined_format(self, parser: ApacheAccessParser) -> None:
        """Test parsing combined log format."""
        line = '192.168.1.1 - user1 [15/Jan/2026:10:30:00 +0000] "GET /api/data HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0"'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.metadata["client_ip"] == "192.168.1.1"
        assert entry.metadata["method"] == "GET"
        assert entry.metadata["path"] == "/api/data"
        assert entry.metadata["status_code"] == 200
        assert entry.metadata["bytes_sent"] == 1234
        assert entry.metadata["user_agent"] == "Mozilla/5.0"

    def test_parse_timestamp(self, parser: ApacheAccessParser) -> None:
        """Test timestamp extraction."""
        line = '192.168.1.1 - - [15/Jan/2026:10:30:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.timestamp is not None
        assert entry.timestamp.year == 2026
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 15

    def test_status_to_level_2xx(self, parser: ApacheAccessParser) -> None:
        """Test 2xx status maps to DEBUG."""
        line = '192.168.1.1 - - [15/Jan/2026:10:30:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
        entry = parser.parse_line(line, 1)
        assert entry is not None
        assert entry.level == LogLevel.DEBUG

    def test_status_to_level_4xx(self, parser: ApacheAccessParser) -> None:
        """Test 4xx status maps to WARN."""
        line = '192.168.1.1 - - [15/Jan/2026:10:30:00 +0000] "GET / HTTP/1.1" 404 0 "-" "-"'
        entry = parser.parse_line(line, 1)
        assert entry is not None
        assert entry.level == LogLevel.WARN

    def test_status_to_level_5xx(self, parser: ApacheAccessParser) -> None:
        """Test 5xx status maps to ERROR."""
        line = '192.168.1.1 - - [15/Jan/2026:10:30:00 +0000] "GET / HTTP/1.1" 500 0 "-" "-"'
        entry = parser.parse_line(line, 1)
        assert entry is not None
        assert entry.level == LogLevel.ERROR

    def test_parse_file(self, parser: ApacheAccessParser, nginx_access_file: Path) -> None:
        """Test parsing access log file."""
        entries = list(parser.parse_file(str(nginx_access_file)))
        assert len(entries) > 0

    def test_detect_confidence(self, sample_apache_lines: list[str]) -> None:
        """Test format detection confidence."""
        confidence = ApacheAccessParser.detect_confidence(sample_apache_lines)
        assert confidence > 0.7


class TestApacheErrorParser:
    """Tests for ApacheErrorParser."""

    @pytest.fixture
    def parser(self) -> ApacheErrorParser:
        """Create parser instance."""
        return ApacheErrorParser()

    def test_can_parse_valid_line(self, parser: ApacheErrorParser) -> None:
        """Test can_parse returns True for valid error log lines."""
        line = "[Thu Jan 15 10:30:00.123456 2026] [error] [pid 1234] message"
        assert parser.can_parse(line)

    def test_can_parse_invalid_line(self, parser: ApacheErrorParser) -> None:
        """Test can_parse returns False for invalid lines."""
        assert not parser.can_parse("192.168.1.1 - - access log")
        assert not parser.can_parse("Not an error log")

    def test_parse_error_line(self, parser: ApacheErrorParser) -> None:
        """Test parsing error log line."""
        line = "[Thu Jan 15 10:30:00.123456 2026] [error] [pid 1234] [client 192.168.1.100:54321] Error message"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.ERROR
        assert entry.metadata["pid"] == 1234
        assert entry.metadata["client_ip"] == "192.168.1.100"
        assert entry.message == "Error message"

    def test_parse_warn_line(self, parser: ApacheErrorParser) -> None:
        """Test parsing warning log line."""
        line = "[Thu Jan 15 10:30:00 2026] [warn] [pid 1234] Warning message"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.WARN

    def test_parse_file(self, parser: ApacheErrorParser, nginx_error_file: Path) -> None:
        """Test parsing error log file."""
        entries = list(parser.parse_file(str(nginx_error_file)))
        assert len(entries) > 0
