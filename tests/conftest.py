"""Shared pytest fixtures for log-analyzer-mcp tests."""

import os
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

# Get the test_logs directory
TEST_LOGS_DIR = Path(__file__).parent.parent / "test_logs"


@pytest.fixture
def test_logs_dir() -> Path:
    """Return path to test_logs directory."""
    return TEST_LOGS_DIR


@pytest.fixture
def syslog_file() -> Path:
    """Path to syslog test file."""
    return TEST_LOGS_DIR / "syslog.log"


@pytest.fixture
def nginx_access_file() -> Path:
    """Path to nginx access log test file."""
    return TEST_LOGS_DIR / "nginx_access.log"


@pytest.fixture
def nginx_error_file() -> Path:
    """Path to nginx error log test file."""
    return TEST_LOGS_DIR / "nginx_error.log"


@pytest.fixture
def jsonl_file() -> Path:
    """Path to JSONL test file."""
    return TEST_LOGS_DIR / "app.jsonl"


@pytest.fixture
def python_log_file() -> Path:
    """Path to Python log test file."""
    return TEST_LOGS_DIR / "python_app.log"


@pytest.fixture
def java_log_file() -> Path:
    """Path to Java log test file."""
    return TEST_LOGS_DIR / "java_app.log"


@pytest.fixture
def docker_log_file() -> Path:
    """Path to Docker log test file."""
    return TEST_LOGS_DIR / "docker_container.log"


@pytest.fixture
def kubernetes_log_file() -> Path:
    """Path to Kubernetes log test file."""
    return TEST_LOGS_DIR / "kubernetes_pod.log"


@pytest.fixture
def generic_log_file() -> Path:
    """Path to generic log test file."""
    return TEST_LOGS_DIR / "generic.log"


@pytest.fixture
def malformed_log_file() -> Path:
    """Path to malformed log test file."""
    return TEST_LOGS_DIR / "malformed.log"


@pytest.fixture
def temp_log_file() -> Generator[Path, None, None]:
    """Create a temporary log file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("2026-01-15 10:30:00 INFO Test message 1\n")
        f.write("2026-01-15 10:30:01 ERROR Test error message\n")
        f.write("2026-01-15 10:30:02 DEBUG Test debug message\n")
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    if temp_path.exists():
        os.unlink(temp_path)


@pytest.fixture
def large_temp_file() -> Generator[Path, None, None]:
    """Create a large temporary file for performance testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        for i in range(10000):
            f.write(f"2026-01-15 10:30:{i % 60:02d} INFO Message number {i}\n")
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    if temp_path.exists():
        os.unlink(temp_path)


@pytest.fixture
def gzip_temp_file() -> Generator[Path, None, None]:
    """Create a gzip compressed temporary log file."""
    import gzip as gz

    with tempfile.NamedTemporaryFile(suffix=".log.gz", delete=False) as f:
        temp_path = Path(f.name)

    with gz.open(temp_path, "wt") as f:
        f.write("2026-01-15 10:30:00 INFO Compressed message 1\n")
        f.write("2026-01-15 10:30:01 ERROR Compressed error\n")

    yield temp_path

    # Cleanup
    if temp_path.exists():
        os.unlink(temp_path)


# Sample log lines for quick tests
SAMPLE_SYSLOG_LINES = [
    "Jan 15 10:30:00 myhost sshd[1234]: Accepted password for user",
    "Jan 15 10:30:01 myhost kernel: [12345.678901] eth0: link up",
]

SAMPLE_APACHE_ACCESS_LINES = [
    '192.168.1.1 - - [15/Jan/2026:10:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '10.0.0.1 - admin [15/Jan/2026:10:30:01 +0000] "POST /api/data HTTP/1.1" 500 45 "-" "curl/7.68.0"',
]

SAMPLE_JSONL_LINES = [
    '{"timestamp":"2026-01-15T10:30:00Z","level":"info","message":"Test message"}',
    '{"timestamp":"2026-01-15T10:30:01Z","level":"error","message":"Test error","code":500}',
]

SAMPLE_PYTHON_LINES = [
    "2026-01-15 10:30:00,123 - myapp.main - INFO - Application starting",
    "2026-01-15 10:30:01,456 - myapp.worker - ERROR - Task failed",
]

SAMPLE_JAVA_LINES = [
    "2026-01-15 10:30:00,123 INFO  [main] com.example.App - Starting",
    "2026-01-15 10:30:01,456 ERROR [pool-1-thread-1] com.example.Svc - Failed",
]

SAMPLE_DOCKER_LINES = [
    "2026-01-15T10:30:00.123456789Z stdout F Application starting",
    "2026-01-15T10:30:01.234567890Z stderr F Error message",
]

SAMPLE_KUBERNETES_LINES = [
    '2026-01-15T10:30:00.123Z level=info msg="Pod starting" pod=myapp',
    "I0115 10:30:01.234567 12345 controller.go:123] Starting",
]


@pytest.fixture
def sample_syslog_lines() -> list[str]:
    """Sample syslog lines for testing."""
    return SAMPLE_SYSLOG_LINES.copy()


@pytest.fixture
def sample_apache_lines() -> list[str]:
    """Sample Apache access log lines for testing."""
    return SAMPLE_APACHE_ACCESS_LINES.copy()


@pytest.fixture
def sample_jsonl_lines() -> list[str]:
    """Sample JSONL lines for testing."""
    return SAMPLE_JSONL_LINES.copy()


@pytest.fixture
def sample_python_lines() -> list[str]:
    """Sample Python log lines for testing."""
    return SAMPLE_PYTHON_LINES.copy()


@pytest.fixture
def sample_java_lines() -> list[str]:
    """Sample Java log lines for testing."""
    return SAMPLE_JAVA_LINES.copy()


@pytest.fixture
def sample_docker_lines() -> list[str]:
    """Sample Docker log lines for testing."""
    return SAMPLE_DOCKER_LINES.copy()


@pytest.fixture
def sample_kubernetes_lines() -> list[str]:
    """Sample Kubernetes log lines for testing."""
    return SAMPLE_KUBERNETES_LINES.copy()


# ============================================================================
# Fixtures for analyzer tests
# ============================================================================

@pytest.fixture
def sample_log_entries() -> list:
    """
    Sample ParsedLogEntry objects for analyzer testing.

    Provides a mix of INFO, WARN, ERROR entries with realistic content
    including database errors that can be grouped.
    """
    from datetime import datetime, timedelta

    from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry

    base_time = datetime(2024, 1, 15, 10, 0, 0)

    return [
        ParsedLogEntry(
            line_number=1,
            raw_line="2024-01-15 10:00:00 INFO Application started",
            timestamp=base_time,
            level=LogLevel.INFO,
            message="Application started",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=2,
            raw_line="2024-01-15 10:00:02 INFO Processing request",
            timestamp=base_time + timedelta(seconds=2),
            level=LogLevel.INFO,
            message="Processing request",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=3,
            raw_line="2024-01-15 10:00:05 ERROR Failed to connect to database server at 192.168.1.100",
            timestamp=base_time + timedelta(seconds=5),
            level=LogLevel.ERROR,
            message="Failed to connect to database server at 192.168.1.100",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=4,
            raw_line="2024-01-15 10:00:07 WARN High memory usage detected",
            timestamp=base_time + timedelta(seconds=7),
            level=LogLevel.WARNING,
            message="High memory usage detected",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=5,
            raw_line="2024-01-15 10:00:10 ERROR Failed to connect to database server at 10.0.0.50",
            timestamp=base_time + timedelta(seconds=10),
            level=LogLevel.ERROR,
            message="Failed to connect to database server at 10.0.0.50",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=6,
            raw_line="2024-01-15 10:00:12 INFO Retry successful",
            timestamp=base_time + timedelta(seconds=12),
            level=LogLevel.INFO,
            message="Retry successful",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=7,
            raw_line="2024-01-15 10:00:15 ERROR Null pointer exception in handler",
            timestamp=base_time + timedelta(seconds=15),
            level=LogLevel.ERROR,
            message="Null pointer exception in handler",
            metadata={}
        ),
        ParsedLogEntry(
            line_number=8,
            raw_line="2024-01-15 10:00:18 INFO Request completed",
            timestamp=base_time + timedelta(seconds=18),
            level=LogLevel.INFO,
            message="Request completed",
            metadata={}
        ),
    ]


@pytest.fixture
def sample_log_file(tmp_path: Path) -> Path:
    """
    Create a temporary log file with sample entries for testing.

    Contains a mix of INFO, WARN, and ERROR entries suitable for
    testing analyzers that read files directly.
    """
    log_content = """2024-01-15 10:00:00 INFO Application started
2024-01-15 10:00:02 INFO Processing request from 192.168.1.100
2024-01-15 10:00:05 ERROR Failed to connect to database: connection refused
2024-01-15 10:00:07 WARN High memory usage detected: 85%
2024-01-15 10:00:10 ERROR Failed to connect to database: timeout after 30s
2024-01-15 10:00:12 INFO Retry successful
2024-01-15 10:00:15 ERROR Null pointer exception in handler
2024-01-15 10:00:18 INFO Request completed successfully
2024-01-15 10:00:20 DEBUG Cleanup completed
2024-01-15 10:00:22 INFO Shutdown requested
"""
    log_file = tmp_path / "sample.log"
    log_file.write_text(log_content)
    return log_file


@pytest.fixture
def mock_parser():
    """
    Create a mock parser for analyzer testing.

    Returns a parser that can parse the sample_log_file entries
    and yield ParsedLogEntry objects.
    """
    import re
    from datetime import datetime

    from codesdevs_log_analyzer.models import ParsedLogEntry
    from codesdevs_log_analyzer.parsers.base import BaseLogParser

    class MockParser(BaseLogParser):
        """Simple mock parser for testing."""

        name = "mock"
        description = "Mock parser for testing"
        patterns = [r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"]

        # Pattern to match timestamp level message format
        _pattern = re.compile(
            r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
            r"(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+"
            r"(.+)$"
        )

        def can_parse(self, line: str) -> bool:
            """Check if line can be parsed."""
            return bool(self._pattern.match(line.strip()))

        def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
            """Parse a single log line."""
            line = line.strip()
            if not line:
                return None

            match = self._pattern.match(line)
            if not match:
                return None

            timestamp_str, level_str, message = match.groups()

            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                timestamp = None

            level = self.normalize_level(level_str)

            return self.create_entry(
                line_number=line_number,
                raw_line=line,
                message=message,
                timestamp=timestamp,
                level=level,
                metadata={}
            )

    return MockParser()
