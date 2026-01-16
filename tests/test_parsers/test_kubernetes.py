"""Tests for Kubernetes log parser."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.kubernetes import KubernetesParser


class TestKubernetesParser:
    """Tests for KubernetesParser."""

    @pytest.fixture
    def parser(self) -> KubernetesParser:
        """Create parser instance."""
        return KubernetesParser(default_year=2026)

    def test_can_parse_structured_format(self, parser: KubernetesParser) -> None:
        """Test can_parse returns True for structured format."""
        line = '2026-01-15T10:30:00.123Z level=info msg="Pod starting"'
        assert parser.can_parse(line)

    def test_can_parse_klog_format(self, parser: KubernetesParser) -> None:
        """Test can_parse returns True for klog format."""
        line = "I0115 10:30:00.123456 12345 controller.go:123] Starting"
        assert parser.can_parse(line)

    def test_can_parse_json_format(self, parser: KubernetesParser) -> None:
        """Test can_parse returns True for JSON format."""
        line = '{"ts":"2026-01-15T10:30:00Z","level":"info","msg":"Test"}'
        assert parser.can_parse(line)

    def test_can_parse_invalid_line(self, parser: KubernetesParser) -> None:
        """Test can_parse returns False for invalid lines."""
        assert not parser.can_parse("Jan 15 10:30:00 syslog")
        assert not parser.can_parse("Not a log line")

    def test_parse_structured_format(self, parser: KubernetesParser) -> None:
        """Test parsing structured format."""
        line = '2026-01-15T10:30:00.123Z level=error msg="Failed to connect" service=redis'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Failed to connect"
        assert entry.level == LogLevel.ERROR
        assert entry.metadata["service"] == "redis"
        assert entry.metadata["format"] == "structured"

    def test_parse_klog_info(self, parser: KubernetesParser) -> None:
        """Test parsing klog INFO format."""
        line = "I0115 10:30:00.123456 12345 controller.go:123] Starting controller"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Starting controller"
        assert entry.level == LogLevel.INFO
        assert entry.metadata["source"] == "controller.go:123"
        assert entry.metadata["pid"] == 12345

    def test_parse_klog_error(self, parser: KubernetesParser) -> None:
        """Test parsing klog ERROR format."""
        line = "E0115 10:30:00.123456 12345 handler.go:789] Error processing"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.ERROR

    def test_parse_klog_warning(self, parser: KubernetesParser) -> None:
        """Test parsing klog WARNING format."""
        line = "W0115 10:30:00.123456 12345 cache.go:456] Cache slow"
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.WARN

    def test_parse_json_format(self, parser: KubernetesParser) -> None:
        """Test parsing JSON format."""
        line = '{"ts":"2026-01-15T10:30:00Z","level":"error","msg":"Database failed","error":"timeout"}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Database failed"
        assert entry.level == LogLevel.ERROR
        assert entry.metadata["error"] == "timeout"

    def test_parse_file(self, parser: KubernetesParser, kubernetes_log_file: Path) -> None:
        """Test parsing Kubernetes log file."""
        entries = list(parser.parse_file(str(kubernetes_log_file)))
        assert len(entries) > 0

    def test_detect_confidence(self, sample_kubernetes_lines: list[str]) -> None:
        """Test format detection confidence."""
        confidence = KubernetesParser.detect_confidence(sample_kubernetes_lines)
        assert confidence > 0.7
