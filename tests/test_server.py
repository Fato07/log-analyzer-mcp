"""Integration tests for log analyzer MCP server."""

import json
from datetime import datetime, timedelta

import pytest

from codesdevs_log_analyzer import (
    PARSER_REGISTRY,
    log_analyzer_correlate,
    log_analyzer_diff,
    log_analyzer_extract_errors,
    log_analyzer_multi,
    log_analyzer_parse,
    log_analyzer_search,
    log_analyzer_suggest_patterns,
    log_analyzer_summarize,
    log_analyzer_tail,
    log_analyzer_trace,
    log_analyzer_watch,
    mcp,
)

# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def python_log_file(tmp_path) -> str:
    """Create a Python-style log file."""
    content = """2024-01-15 10:00:00,123 INFO [main] Application starting
2024-01-15 10:00:01,456 DEBUG [config] Loading configuration from /etc/app.conf
2024-01-15 10:00:02,789 INFO [database] Connecting to database
2024-01-15 10:00:05,012 ERROR [database] Connection failed: Connection refused
2024-01-15 10:00:06,345 WARN [database] Retrying connection (attempt 1/3)
2024-01-15 10:00:10,678 ERROR [database] Connection failed: Connection refused
2024-01-15 10:00:11,901 WARN [database] Retrying connection (attempt 2/3)
2024-01-15 10:00:15,234 INFO [database] Connection established
2024-01-15 10:00:20,567 ERROR [service] NullPointerException in UserService
Traceback (most recent call last):
  File "/app/service.py", line 42, in process
    user = self.get_user(user_id)
  File "/app/service.py", line 55, in get_user
    return self.db.query(User).filter_by(id=user_id).first()
NullPointerException: user_id was None
2024-01-15 10:00:25,890 INFO [api] Request completed in 150ms
2024-01-15 10:00:30,123 WARN [system] High memory usage: 85%
2024-01-15 10:00:35,456 INFO [api] Health check passed
"""
    log_file = tmp_path / "python_app.log"
    log_file.write_text(content)
    return str(log_file)


@pytest.fixture
def syslog_file(tmp_path) -> str:
    """Create a syslog-style log file."""
    content = """Jan 15 10:00:00 server1 sshd[1234]: Accepted publickey for user from 192.168.1.100
Jan 15 10:00:01 server1 sshd[1234]: pam_unix(sshd:session): session opened
Jan 15 10:00:05 server1 kernel: [ERROR] disk I/O error on sda1
Jan 15 10:00:10 server1 nginx[5678]: 192.168.1.100 - GET /api/health 200
Jan 15 10:00:15 server1 nginx[5678]: 192.168.1.200 - POST /api/login 401
Jan 15 10:00:20 server1 app[9012]: [WARN] Rate limit exceeded for IP 192.168.1.200
"""
    log_file = tmp_path / "syslog.log"
    log_file.write_text(content)
    return str(log_file)


@pytest.fixture
def jsonl_log_file(tmp_path) -> str:
    """Create a JSON Lines log file."""
    lines = [
        {"timestamp": "2024-01-15T10:00:00Z", "level": "INFO", "message": "Starting", "service": "api"},
        {"timestamp": "2024-01-15T10:00:01Z", "level": "DEBUG", "message": "Config loaded", "service": "api"},
        {"timestamp": "2024-01-15T10:00:05Z", "level": "ERROR", "message": "Database error", "service": "db"},
        {"timestamp": "2024-01-15T10:00:10Z", "level": "INFO", "message": "Request completed", "service": "api"},
    ]
    content = "\n".join(json.dumps(line) for line in lines)
    log_file = tmp_path / "app.jsonl"
    log_file.write_text(content)
    return str(log_file)


@pytest.fixture
def large_log_file(tmp_path) -> str:
    """Create a large log file with many entries."""
    base_time = datetime(2024, 1, 15, 10, 0, 0)
    lines = []

    for i in range(1000):
        ts = base_time + timedelta(seconds=i)
        level = ["INFO", "DEBUG", "WARN", "ERROR"][i % 4]
        if level == "ERROR":
            lines.append(f"{ts.isoformat()} {level} Error message type {i % 5}: Operation failed")
        else:
            lines.append(f"{ts.isoformat()} {level} Log message {i}")

    log_file = tmp_path / "large.log"
    log_file.write_text("\n".join(lines))
    return str(log_file)


# =============================================================================
# Server Import Tests
# =============================================================================


class TestServerImport:
    """Tests for server module imports and tool availability."""

    def test_mcp_server_exists(self):
        """Test that MCP server is properly initialized."""
        assert mcp is not None
        assert mcp.name == "log_analyzer_mcp"

    def test_all_tools_registered(self):
        """Test that all 14 tools are registered."""
        tools = mcp._tool_manager._tools
        assert len(tools) == 14, f"Expected 14 tools, got {len(tools)}"

    def test_tool_functions_callable(self):
        """Test that all tool functions are callable."""
        tools = [
            log_analyzer_parse,
            log_analyzer_search,
            log_analyzer_extract_errors,
            log_analyzer_summarize,
            log_analyzer_tail,
            log_analyzer_correlate,
            log_analyzer_diff,
            log_analyzer_watch,
            log_analyzer_suggest_patterns,
            log_analyzer_trace,
            log_analyzer_multi,
        ]
        for tool in tools:
            assert callable(tool), f"{tool.__name__} is not callable"

    def test_parser_registry_populated(self):
        """Test that parser registry has all expected parsers."""
        expected_parsers = [
            "syslog", "apache_access", "apache_error", "jsonl",
            "python", "java", "docker", "kubernetes", "generic"
        ]
        for parser_name in expected_parsers:
            assert parser_name in PARSER_REGISTRY, f"Missing parser: {parser_name}"


# =============================================================================
# Tool: log_analyzer_parse Tests
# =============================================================================


class TestLogAnalyzerParse:
    """Tests for log_analyzer_parse tool."""

    def test_parse_python_log(self, python_log_file):
        """Test parsing a Python-style log file."""
        result = log_analyzer_parse(python_log_file)

        assert "Log Analysis Results" in result
        assert python_log_file in result
        assert "Level Distribution" in result

    def test_parse_with_json_format(self, python_log_file):
        """Test parsing with JSON output format."""
        result = log_analyzer_parse(python_log_file, response_format="json")

        data = json.loads(result)
        assert "file" in data
        assert "format" in data
        assert "lines" in data
        assert data["lines"]["total"] > 0

    def test_parse_with_format_hint(self, python_log_file):
        """Test parsing with explicit format hint."""
        result = log_analyzer_parse(python_log_file, format_hint="generic")

        assert "generic" in result.lower()

    def test_parse_detects_levels(self, python_log_file):
        """Test that level distribution is detected."""
        result = log_analyzer_parse(python_log_file, response_format="json")

        data = json.loads(result)
        assert "levels" in data
        # Should have at least INFO and ERROR
        assert len(data["levels"]) > 0

    def test_parse_file_not_found(self):
        """Test error handling for missing file."""
        result = log_analyzer_parse("/nonexistent/file.log")

        assert "Error" in result
        assert "not found" in result.lower()

    def test_parse_invalid_format_hint(self, python_log_file):
        """Test error handling for invalid format hint."""
        result = log_analyzer_parse(python_log_file, format_hint="invalid_format")

        assert "Error" in result or "Unknown format" in result


# =============================================================================
# Tool: log_analyzer_search Tests
# =============================================================================


class TestLogAnalyzerSearch:
    """Tests for log_analyzer_search tool."""

    def test_search_simple_pattern(self, python_log_file):
        """Test simple text search."""
        result = log_analyzer_search(python_log_file, pattern="ERROR")

        assert "Search Results" in result
        assert "Match" in result

    def test_search_with_regex(self, python_log_file):
        """Test regex pattern search."""
        result = log_analyzer_search(
            python_log_file,
            pattern=r"Connection.*failed",
            is_regex=True
        )

        assert "Match" in result or "matches" in result.lower()

    def test_search_json_output(self, python_log_file):
        """Test search with JSON output."""
        result = log_analyzer_search(
            python_log_file,
            pattern="ERROR",
            response_format="json"
        )

        data = json.loads(result)
        assert "pattern" in data
        assert "matches" in data
        assert "total_matches" in data

    def test_search_with_context(self, python_log_file):
        """Test search with context lines."""
        result = log_analyzer_search(
            python_log_file,
            pattern="NullPointerException",
            context_lines=5
        )

        # Should include context around match
        assert "Match" in result

    def test_search_case_sensitive(self, python_log_file):
        """Test case-sensitive search."""
        result_sensitive = log_analyzer_search(
            python_log_file,
            pattern="error",
            case_sensitive=True,
            response_format="json"
        )
        result_insensitive = log_analyzer_search(
            python_log_file,
            pattern="error",
            case_sensitive=False,
            response_format="json"
        )

        data_sensitive = json.loads(result_sensitive)
        data_insensitive = json.loads(result_insensitive)

        # Case-insensitive should find more or equal matches
        assert data_insensitive["total_matches"] >= data_sensitive["total_matches"]

    def test_search_no_matches(self, python_log_file):
        """Test search with no matches."""
        result = log_analyzer_search(
            python_log_file,
            pattern="xyz_nonexistent_pattern_123",
            response_format="json"
        )

        data = json.loads(result)
        assert data["total_matches"] == 0


# =============================================================================
# Tool: log_analyzer_extract_errors Tests
# =============================================================================


class TestLogAnalyzerExtractErrors:
    """Tests for log_analyzer_extract_errors tool."""

    def test_extract_errors_basic(self, python_log_file):
        """Test basic error extraction."""
        result = log_analyzer_extract_errors(python_log_file)

        assert "Error Extraction Results" in result
        assert "Total Errors" in result

    def test_extract_errors_json(self, python_log_file):
        """Test error extraction with JSON output."""
        result = log_analyzer_extract_errors(python_log_file, response_format="json")

        data = json.loads(result)
        assert "total_errors" in data
        assert "error_groups" in data
        assert data["total_errors"] > 0

    def test_extract_errors_with_warnings(self, python_log_file):
        """Test error extraction including warnings."""
        result_no_warnings = log_analyzer_extract_errors(
            python_log_file,
            include_warnings=False,
            response_format="json"
        )
        result_with_warnings = log_analyzer_extract_errors(
            python_log_file,
            include_warnings=True,
            response_format="json"
        )

        _data_no = json.loads(result_no_warnings)  # noqa: F841
        data_with = json.loads(result_with_warnings)

        assert data_with["total_warnings"] >= 0

    def test_extract_errors_grouping(self, large_log_file):
        """Test that similar errors are grouped."""
        result = log_analyzer_extract_errors(
            large_log_file,
            group_similar=True,
            response_format="json"
        )

        data = json.loads(result)
        # Should have fewer unique groups than total errors
        assert data["unique_errors"] <= data["total_errors"]


# =============================================================================
# Tool: log_analyzer_summarize Tests
# =============================================================================


class TestLogAnalyzerSummarize:
    """Tests for log_analyzer_summarize tool."""

    def test_summarize_basic(self, python_log_file):
        """Test basic log summary."""
        result = log_analyzer_summarize(python_log_file)

        assert "Log Summary" in result
        assert "Level Distribution" in result

    def test_summarize_json(self, python_log_file):
        """Test summary with JSON output."""
        result = log_analyzer_summarize(python_log_file, response_format="json")

        data = json.loads(result)
        assert "file" in data
        assert "level_distribution" in data
        assert "top_errors" in data

    def test_summarize_recommendations(self, python_log_file):
        """Test that summary includes recommendations."""
        result = log_analyzer_summarize(python_log_file, response_format="json")

        data = json.loads(result)
        assert "recommendations" in data

    def test_summarize_large_file(self, large_log_file):
        """Test summary on larger file."""
        result = log_analyzer_summarize(large_log_file, max_lines=500)

        assert "Log Summary" in result


# =============================================================================
# Tool: log_analyzer_tail Tests
# =============================================================================


class TestLogAnalyzerTail:
    """Tests for log_analyzer_tail tool."""

    def test_tail_basic(self, python_log_file):
        """Test basic tail operation."""
        result = log_analyzer_tail(python_log_file, lines=5)

        assert "Recent Log Entries" in result

    def test_tail_json(self, python_log_file):
        """Test tail with JSON output."""
        result = log_analyzer_tail(python_log_file, lines=5, response_format="json")

        data = json.loads(result)
        assert "entries" in data
        assert data["lines_returned"] <= 5

    def test_tail_level_filter(self, python_log_file):
        """Test tail with level filter."""
        result = log_analyzer_tail(
            python_log_file,
            lines=100,
            level_filter="ERROR",
            response_format="json"
        )

        data = json.loads(result)
        # All returned entries should be ERROR level
        for entry in data["entries"]:
            if entry["level"]:
                assert entry["level"] == "ERROR"


# =============================================================================
# Tool: log_analyzer_correlate Tests
# =============================================================================


class TestLogAnalyzerCorrelate:
    """Tests for log_analyzer_correlate tool."""

    def test_correlate_basic(self, python_log_file):
        """Test basic correlation."""
        result = log_analyzer_correlate(
            python_log_file,
            anchor_pattern="ERROR"
        )

        assert "Correlation Results" in result

    def test_correlate_json(self, python_log_file):
        """Test correlation with JSON output."""
        result = log_analyzer_correlate(
            python_log_file,
            anchor_pattern="Connection",
            response_format="json"
        )

        data = json.loads(result)
        assert "anchor_pattern" in data
        assert "windows" in data

    def test_correlate_time_window(self, python_log_file):
        """Test correlation with custom time window."""
        result = log_analyzer_correlate(
            python_log_file,
            anchor_pattern="ERROR",
            window_seconds=30,
            response_format="json"
        )

        data = json.loads(result)
        assert data["window_seconds"] == 30

    def test_correlate_invalid_regex(self, python_log_file):
        """Test correlation with invalid regex."""
        result = log_analyzer_correlate(
            python_log_file,
            anchor_pattern="[invalid("
        )

        assert "Error" in result or "Invalid" in result


# =============================================================================
# Tool: log_analyzer_diff Tests
# =============================================================================


class TestLogAnalyzerDiff:
    """Tests for log_analyzer_diff tool."""

    def test_diff_two_files(self, python_log_file, syslog_file):
        """Test diff between two files."""
        result = log_analyzer_diff(python_log_file, syslog_file)

        assert "Log Diff Results" in result
        assert "Summary" in result

    def test_diff_json(self, python_log_file, syslog_file):
        """Test diff with JSON output."""
        result = log_analyzer_diff(
            python_log_file,
            syslog_file,
            response_format="json"
        )

        data = json.loads(result)
        assert "summary" in data
        assert "new_errors" in data
        assert "resolved_errors" in data

    def test_diff_same_file(self, python_log_file):
        """Test diff same file (no differences expected)."""
        result = log_analyzer_diff(
            python_log_file,
            python_log_file,
            response_format="json"
        )

        data = json.loads(result)
        # Same file should have no new or resolved errors
        assert len(data["new_errors"]) == 0
        assert len(data["resolved_errors"]) == 0

    def test_diff_file_not_found(self):
        """Test diff with missing file."""
        result = log_analyzer_diff("/nonexistent/a.log", "/nonexistent/b.log")

        assert "Error" in result


# =============================================================================
# Output Format Tests
# =============================================================================


class TestOutputFormats:
    """Tests for output format support across tools."""

    def test_markdown_format_parse(self, python_log_file):
        """Test markdown output for parse tool."""
        result = log_analyzer_parse(python_log_file, response_format="markdown")
        assert "##" in result  # Markdown headers
        assert "**" in result  # Bold text

    def test_json_format_parse(self, python_log_file):
        """Test JSON output for parse tool."""
        result = log_analyzer_parse(python_log_file, response_format="json")
        data = json.loads(result)  # Should not raise
        assert isinstance(data, dict)

    def test_all_tools_support_both_formats(self, python_log_file):
        """Test that all tools support both output formats."""
        tools_with_args = [
            (log_analyzer_parse, {"file_path": python_log_file}),
            (log_analyzer_search, {"file_path": python_log_file, "pattern": "test"}),
            (log_analyzer_extract_errors, {"file_path": python_log_file}),
            (log_analyzer_summarize, {"file_path": python_log_file}),
            (log_analyzer_tail, {"file_path": python_log_file}),
            (log_analyzer_correlate, {"file_path": python_log_file, "anchor_pattern": "test"}),
            (log_analyzer_diff, {"file_path_a": python_log_file}),
        ]

        for tool, args in tools_with_args:
            # Test markdown
            md_result = tool(**args, response_format="markdown")
            assert isinstance(md_result, str)

            # Test JSON
            json_result = tool(**args, response_format="json")
            json.loads(json_result)  # Should not raise


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling across tools."""

    def test_file_not_found_all_tools(self):
        """Test file not found error handling for all tools."""
        fake_path = "/nonexistent/path/to/file.log"

        tools = [
            lambda: log_analyzer_parse(fake_path),
            lambda: log_analyzer_search(fake_path, pattern="test"),
            lambda: log_analyzer_extract_errors(fake_path),
            lambda: log_analyzer_summarize(fake_path),
            lambda: log_analyzer_tail(fake_path),
            lambda: log_analyzer_correlate(fake_path, anchor_pattern="test"),
            lambda: log_analyzer_diff(fake_path),
        ]

        for tool in tools:
            result = tool()
            assert "Error" in result
            assert "not found" in result.lower()

    def test_directory_instead_of_file(self, tmp_path):
        """Test error when given directory instead of file."""
        result = log_analyzer_parse(str(tmp_path))
        assert "Error" in result

    def test_empty_file(self, tmp_path):
        """Test handling of empty file."""
        empty_file = tmp_path / "empty.log"
        empty_file.write_text("")

        result = log_analyzer_parse(str(empty_file))
        # Should not crash, should return valid result
        assert isinstance(result, str)


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """End-to-end integration tests."""

    def test_full_analysis_workflow(self, python_log_file):
        """Test a complete analysis workflow."""
        # 1. Parse the file
        parse_result = log_analyzer_parse(python_log_file, response_format="json")
        parse_data = json.loads(parse_result)
        assert parse_data["lines"]["total"] > 0

        # 2. Search for errors
        search_result = log_analyzer_search(
            python_log_file,
            pattern="ERROR",
            response_format="json"
        )
        _search_data = json.loads(search_result)  # noqa: F841

        # 3. Extract errors
        errors_result = log_analyzer_extract_errors(python_log_file, response_format="json")
        _errors_data = json.loads(errors_result)  # noqa: F841

        # 4. Summarize
        summary_result = log_analyzer_summarize(python_log_file, response_format="json")
        summary_data = json.loads(summary_result)

        # Verify consistency
        assert summary_data["lines"]["total"] == parse_data["lines"]["total"]

    def test_jsonl_file_workflow(self, jsonl_log_file):
        """Test workflow with JSONL log file."""
        # Parse should detect JSONL format
        result = log_analyzer_parse(jsonl_log_file, response_format="json")
        data = json.loads(result)

        # Should detect as JSONL with good confidence
        assert data["format"]["confidence"] > 0.5
