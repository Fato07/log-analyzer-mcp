"""Shared pytest fixtures for log analyzer tests."""

import os
import tempfile
from datetime import datetime, timedelta
from typing import Iterator

import pytest

from log_analyzer_mcp.parsers.base import BaseLogParser, ParsedLogEntry


class MockParser(BaseLogParser):
    """Mock parser for testing."""

    name = "mock"
    patterns = []

    def can_parse(self, line: str) -> bool:
        return True

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        # Simple mock parsing
        level = None
        timestamp = None

        # Try to extract level
        for lvl in ['ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG']:
            if lvl in line.upper():
                level = lvl
                break

        # Try to extract timestamp (ISO format)
        import re
        ts_match = re.search(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', line)
        if ts_match:
            try:
                from dateutil import parser as date_parser
                timestamp = date_parser.parse(ts_match.group(1))
            except Exception:
                pass

        return ParsedLogEntry(
            line_number=line_number,
            raw_line=line,
            timestamp=timestamp,
            level=level,
            message=line,
            metadata={}
        )


@pytest.fixture
def mock_parser() -> MockParser:
    """Provide a mock parser for testing."""
    return MockParser()


@pytest.fixture
def sample_log_entries() -> list[ParsedLogEntry]:
    """Provide sample log entries for testing."""
    base_time = datetime(2024, 1, 15, 10, 0, 0)
    entries = [
        ParsedLogEntry(
            line_number=1,
            raw_line="2024-01-15 10:00:00 INFO Starting application",
            timestamp=base_time,
            level="INFO",
            message="Starting application",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=2,
            raw_line="2024-01-15 10:00:01 DEBUG Loading configuration",
            timestamp=base_time + timedelta(seconds=1),
            level="DEBUG",
            message="Loading configuration",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=3,
            raw_line="2024-01-15 10:00:05 ERROR Failed to connect to database: Connection refused",
            timestamp=base_time + timedelta(seconds=5),
            level="ERROR",
            message="Failed to connect to database: Connection refused",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=4,
            raw_line="2024-01-15 10:00:06 WARN Retrying connection attempt 1/3",
            timestamp=base_time + timedelta(seconds=6),
            level="WARN",
            message="Retrying connection attempt 1/3",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=5,
            raw_line="2024-01-15 10:00:10 ERROR Failed to connect to database: Connection refused",
            timestamp=base_time + timedelta(seconds=10),
            level="ERROR",
            message="Failed to connect to database: Connection refused",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=6,
            raw_line="2024-01-15 10:00:15 INFO Connection established",
            timestamp=base_time + timedelta(seconds=15),
            level="INFO",
            message="Connection established",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=7,
            raw_line="2024-01-15 10:00:20 ERROR NullPointerException in UserService",
            timestamp=base_time + timedelta(seconds=20),
            level="ERROR",
            message="NullPointerException in UserService",
            metadata={}
        ),
    ]
    return entries


@pytest.fixture
def sample_log_file(tmp_path) -> str:
    """Create a temporary log file for testing."""
    log_content = """2024-01-15 10:00:00 INFO Starting application
2024-01-15 10:00:01 DEBUG Loading configuration
2024-01-15 10:00:05 ERROR Failed to connect to database: Connection refused
2024-01-15 10:00:06 WARN Retrying connection attempt 1/3
2024-01-15 10:00:10 ERROR Failed to connect to database: Connection refused
2024-01-15 10:00:15 INFO Connection established
2024-01-15 10:00:20 ERROR NullPointerException in UserService
Traceback (most recent call last):
  File "/app/service.py", line 42, in process
    user = self.get_user(user_id)
  File "/app/service.py", line 55, in get_user
    return self.db.query(User).filter_by(id=user_id).first()
NullPointerException: user_id was None
2024-01-15 10:00:25 INFO Request completed in 150ms
2024-01-15 10:00:30 WARN High memory usage detected: 85%
"""
    log_file = tmp_path / "test.log"
    log_file.write_text(log_content)
    return str(log_file)


@pytest.fixture
def sample_web_log_file(tmp_path) -> str:
    """Create a temporary web access log file for testing."""
    log_content = """2024-01-15 10:00:00 INFO 192.168.1.1 GET /api/users 200 150ms
2024-01-15 10:00:01 INFO 192.168.1.2 GET /api/users/123 200 50ms
2024-01-15 10:00:02 WARN 192.168.1.1 POST /api/login 401 10ms
2024-01-15 10:00:03 WARN 192.168.1.1 POST /api/login 401 10ms
2024-01-15 10:00:04 WARN 192.168.1.1 POST /api/login 401 10ms
2024-01-15 10:00:05 ERROR 192.168.1.3 GET /api/users/999 500 5000ms
2024-01-15 10:00:10 INFO 192.168.1.2 GET /api/products 200 200ms
2024-01-15 10:05:00 INFO 192.168.1.1 GET /api/health 200 5ms
"""
    log_file = tmp_path / "access.log"
    log_file.write_text(log_content)
    return str(log_file)


@pytest.fixture
def entries_iterator(sample_log_entries: list[ParsedLogEntry]) -> Iterator[ParsedLogEntry]:
    """Provide an iterator of log entries."""
    return iter(sample_log_entries)
