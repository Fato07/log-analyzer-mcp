"""Tests for Docker log parser."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.docker import DockerParser


class TestDockerParser:
    """Tests for DockerParser."""

    @pytest.fixture
    def parser(self) -> DockerParser:
        """Create parser instance."""
        return DockerParser()

    def test_can_parse_native_format(self, parser: DockerParser) -> None:
        """Test can_parse returns True for native Docker format."""
        line = "2026-01-15T10:30:00.123456789Z stdout F Message"
        assert parser.can_parse(line)

    def test_can_parse_json_format(self, parser: DockerParser) -> None:
        """Test can_parse returns True for JSON format."""
        line = '{"log":"Message\\n","stream":"stdout","time":"2026-01-15T10:30:00Z"}'
        assert parser.can_parse(line)

    def test_can_parse_invalid_line(self, parser: DockerParser) -> None:
        """Test can_parse returns False for invalid lines."""
        assert not parser.can_parse("2026-01-15 10:30:00 INFO Not docker")
        assert not parser.can_parse("Not a log line")

    def test_parse_native_stdout(self, parser: DockerParser) -> None:
        """Test parsing native Docker stdout format."""
        line = "2026-01-15T10:30:00.123456789Z stdout F Application started"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Application started"
        assert entry.level == LogLevel.INFO
        assert entry.metadata["stream"] == "stdout"
        assert entry.metadata["format"] == "native"

    def test_parse_native_stderr(self, parser: DockerParser) -> None:
        """Test parsing native Docker stderr format."""
        line = "2026-01-15T10:30:00.123456789Z stderr F Error message"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.ERROR
        assert entry.metadata["stream"] == "stderr"

    def test_parse_native_partial(self, parser: DockerParser) -> None:
        """Test parsing partial message flag."""
        line = "2026-01-15T10:30:00.123456789Z stdout P Partial message"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.metadata.get("partial") is True

    def test_parse_json_format(self, parser: DockerParser) -> None:
        """Test parsing JSON Docker format."""
        line = '{"log":"Test message\\n","stream":"stdout","time":"2026-01-15T10:30:00.123Z"}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Test message"
        assert entry.level == LogLevel.INFO
        assert entry.metadata["format"] == "json"

    def test_parse_timestamp(self, parser: DockerParser) -> None:
        """Test timestamp extraction."""
        line = "2026-01-15T10:30:00.123456789Z stdout F test"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.timestamp is not None
        assert entry.timestamp.year == 2026

    def test_parse_file(self, parser: DockerParser, docker_log_file: Path) -> None:
        """Test parsing Docker log file."""
        entries = list(parser.parse_file(str(docker_log_file)))
        assert len(entries) > 0

    def test_detect_confidence(self, sample_docker_lines: list[str]) -> None:
        """Test format detection confidence."""
        confidence = DockerParser.detect_confidence(sample_docker_lines)
        assert confidence > 0.7
