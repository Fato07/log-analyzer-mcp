"""Tests for JSONL parser."""

from pathlib import Path

import pytest

from codesdevs_log_analyzer.models import LogLevel
from codesdevs_log_analyzer.parsers.jsonl import JSONLParser


class TestJSONLParser:
    """Tests for JSONLParser."""

    @pytest.fixture
    def parser(self) -> JSONLParser:
        """Create parser instance."""
        return JSONLParser()

    def test_can_parse_valid_json(self, parser: JSONLParser) -> None:
        """Test can_parse returns True for valid JSON."""
        assert parser.can_parse('{"message": "test"}')
        assert parser.can_parse('{"level": "info", "msg": "test"}')

    def test_can_parse_invalid_json(self, parser: JSONLParser) -> None:
        """Test can_parse returns False for invalid JSON."""
        assert not parser.can_parse("Not JSON")
        assert not parser.can_parse('{"incomplete": ')
        assert not parser.can_parse("")

    def test_parse_standard_fields(self, parser: JSONLParser) -> None:
        """Test parsing with standard field names."""
        line = '{"timestamp":"2026-01-15T10:30:00Z","level":"info","message":"Test message"}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Test message"
        assert entry.level == LogLevel.INFO
        assert entry.timestamp is not None

    def test_parse_alternative_field_names(self, parser: JSONLParser) -> None:
        """Test parsing with alternative field names."""
        line = '{"ts":"2026-01-15T10:30:00Z","lvl":"error","msg":"Error occurred"}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.message == "Error occurred"
        assert entry.level == LogLevel.ERROR

    def test_parse_bunyan_numeric_levels(self, parser: JSONLParser) -> None:
        """Test parsing Bunyan numeric levels."""
        line = '{"time":"2026-01-15T10:30:00Z","level":50,"msg":"Error"}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.level == LogLevel.ERROR

    def test_parse_unix_timestamp(self, parser: JSONLParser) -> None:
        """Test parsing Unix epoch timestamp."""
        line = '{"ts":1736934600000,"level":"info","msg":"Test"}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.timestamp is not None

    def test_parse_extra_fields(self, parser: JSONLParser) -> None:
        """Test extra fields go to metadata."""
        line = '{"timestamp":"2026-01-15T10:30:00Z","level":"info","message":"Test","user_id":42,"request_id":"abc"}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert entry.metadata["user_id"] == 42
        assert entry.metadata["request_id"] == "abc"

    def test_parse_nested_objects(self, parser: JSONLParser) -> None:
        """Test nested objects are flattened."""
        line = '{"timestamp":"2026-01-15T10:30:00Z","message":"Test","context":{"user":"test","ip":"1.2.3.4"}}'
        entry = parser.parse_line(line, 1)

        assert entry is not None
        assert "context.user" in entry.metadata
        assert entry.metadata["context.user"] == "test"

    def test_parse_file(self, parser: JSONLParser, jsonl_file: Path) -> None:
        """Test parsing JSONL file."""
        entries = list(parser.parse_file(str(jsonl_file)))
        assert len(entries) > 0

    def test_detect_confidence(self, sample_jsonl_lines: list[str]) -> None:
        """Test format detection confidence."""
        confidence = JSONLParser.detect_confidence(sample_jsonl_lines)
        assert confidence > 0.7
