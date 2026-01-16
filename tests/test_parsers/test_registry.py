"""Tests for parser registry and auto-detection."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogFormat
from codesdevs_log_analyzer.parsers import (
    get_parser,
    detect_format,
    detect_format_from_lines,
    list_formats,
    get_parser_for_format,
    PARSER_REGISTRY,
    SyslogParser,
    ApacheAccessParser,
    JSONLParser,
    DockerParser,
    KubernetesParser,
    GenericParser,
)


class TestParserRegistry:
    """Tests for parser registry."""

    def test_registry_contains_all_parsers(self) -> None:
        """Test registry has all expected parsers."""
        expected = [
            "syslog",
            "apache_access",
            "apache_error",
            "jsonl",
            "python",
            "java",
            "docker",
            "kubernetes",
            "generic",
        ]
        for name in expected:
            assert name in PARSER_REGISTRY

    def test_get_parser_by_name(self) -> None:
        """Test getting parser by string name."""
        parser = get_parser("syslog")
        assert isinstance(parser, SyslogParser)

    def test_get_parser_by_enum(self) -> None:
        """Test getting parser by LogFormat enum."""
        parser = get_parser(LogFormat.JSONL)
        assert isinstance(parser, JSONLParser)

    def test_get_parser_invalid_name(self) -> None:
        """Test getting parser with invalid name raises error."""
        with pytest.raises(ValueError):
            get_parser("invalid_format")

    def test_get_parser_auto_raises(self) -> None:
        """Test getting parser with AUTO raises error."""
        with pytest.raises(ValueError):
            get_parser(LogFormat.AUTO)

    def test_get_parser_for_format(self) -> None:
        """Test get_parser_for_format function."""
        parser = get_parser_for_format(LogFormat.DOCKER)
        assert isinstance(parser, DockerParser)

    def test_get_parser_for_format_auto_raises(self) -> None:
        """Test get_parser_for_format with AUTO raises error."""
        with pytest.raises(ValueError):
            get_parser_for_format(LogFormat.AUTO)

    def test_list_formats(self) -> None:
        """Test listing available formats."""
        formats = list_formats()
        assert len(formats) == len(PARSER_REGISTRY)
        assert all("name" in f and "description" in f for f in formats)


class TestFormatDetection:
    """Tests for format auto-detection."""

    def test_detect_syslog(self, syslog_file: Path) -> None:
        """Test detecting syslog format."""
        parser, confidence = detect_format(str(syslog_file))
        assert isinstance(parser, SyslogParser)
        assert confidence > 0.7

    def test_detect_apache_access(self, nginx_access_file: Path) -> None:
        """Test detecting Apache access log format."""
        parser, confidence = detect_format(str(nginx_access_file))
        assert isinstance(parser, ApacheAccessParser)
        assert confidence > 0.7

    def test_detect_jsonl(self, jsonl_file: Path) -> None:
        """Test detecting JSONL format."""
        parser, confidence = detect_format(str(jsonl_file))
        assert isinstance(parser, JSONLParser)
        assert confidence > 0.7

    def test_detect_docker(self, docker_log_file: Path) -> None:
        """Test detecting Docker format."""
        parser, confidence = detect_format(str(docker_log_file))
        assert isinstance(parser, DockerParser)
        assert confidence > 0.5

    def test_detect_kubernetes(self, kubernetes_log_file: Path) -> None:
        """Test detecting Kubernetes format."""
        parser, confidence = detect_format(str(kubernetes_log_file))
        assert isinstance(parser, KubernetesParser)
        assert confidence > 0.5

    def test_detect_from_lines_syslog(self, sample_syslog_lines: list[str]) -> None:
        """Test detecting format from syslog lines."""
        parser, confidence = detect_format_from_lines(sample_syslog_lines)
        assert isinstance(parser, SyslogParser)

    def test_detect_from_lines_jsonl(self, sample_jsonl_lines: list[str]) -> None:
        """Test detecting format from JSONL lines."""
        parser, confidence = detect_format_from_lines(sample_jsonl_lines)
        assert isinstance(parser, JSONLParser)

    def test_detect_from_lines_docker(self, sample_docker_lines: list[str]) -> None:
        """Test detecting format from Docker lines."""
        parser, confidence = detect_format_from_lines(sample_docker_lines)
        assert isinstance(parser, DockerParser)

    def test_detect_empty_returns_generic(self) -> None:
        """Test empty input returns generic parser."""
        parser, confidence = detect_format_from_lines([])
        assert isinstance(parser, GenericParser)
        assert confidence == 0.0

    def test_detect_generic_fallback(self) -> None:
        """Test generic fallback for unrecognized format."""
        lines = [
            "Some random text",
            "More random text",
            "Nothing structured here",
        ]
        parser, confidence = detect_format_from_lines(lines)
        # Should return some parser (likely generic)
        assert parser is not None
