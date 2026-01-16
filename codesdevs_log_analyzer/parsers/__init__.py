"""Parser registry and auto-detection for log formats."""

from codesdevs_log_analyzer.models import LogFormat, ParsedLogEntry
from codesdevs_log_analyzer.parsers.apache import ApacheAccessParser, ApacheErrorParser
from codesdevs_log_analyzer.parsers.base import BaseLogParser
from codesdevs_log_analyzer.parsers.docker import DockerParser
from codesdevs_log_analyzer.parsers.generic import GenericParser
from codesdevs_log_analyzer.parsers.java import JavaLogParser
from codesdevs_log_analyzer.parsers.jsonl import JSONLParser
from codesdevs_log_analyzer.parsers.kubernetes import KubernetesParser
from codesdevs_log_analyzer.parsers.python_log import PythonLogParser
from codesdevs_log_analyzer.parsers.syslog import SyslogParser
from codesdevs_log_analyzer.utils.file_handler import stream_file

# Parser registry mapping format names to parser classes
PARSER_REGISTRY: dict[str, type[BaseLogParser]] = {
    "syslog": SyslogParser,
    "apache_access": ApacheAccessParser,
    "apache_error": ApacheErrorParser,
    "jsonl": JSONLParser,
    "python": PythonLogParser,
    "java": JavaLogParser,
    "docker": DockerParser,
    "kubernetes": KubernetesParser,
    "generic": GenericParser,
}

# Mapping from LogFormat enum to parser names
FORMAT_TO_PARSER: dict[LogFormat, str] = {
    LogFormat.SYSLOG: "syslog",
    LogFormat.APACHE_ACCESS: "apache_access",
    LogFormat.APACHE_ERROR: "apache_error",
    LogFormat.JSONL: "jsonl",
    LogFormat.PYTHON: "python",
    LogFormat.JAVA: "java",
    LogFormat.DOCKER: "docker",
    LogFormat.KUBERNETES: "kubernetes",
    LogFormat.GENERIC: "generic",
}

# Detection order - more specific parsers first
DETECTION_ORDER: list[str] = [
    "docker",  # Very specific format
    "kubernetes",  # Specific structured format
    "apache_access",  # Specific combined log format
    "apache_error",  # Specific error format
    "jsonl",  # JSON format
    "java",  # Java logging format
    "python",  # Python logging format
    "syslog",  # Common syslog format
    "generic",  # Fallback (always last)
]


def get_parser(format_name: str | LogFormat) -> BaseLogParser:
    """
    Get parser instance by format name.

    Args:
        format_name: Parser name string or LogFormat enum

    Returns:
        Instantiated parser

    Raises:
        ValueError: If format name is not recognized
    """
    # Handle LogFormat enum
    if isinstance(format_name, LogFormat):
        if format_name == LogFormat.AUTO:
            raise ValueError("Use detect_format() for auto-detection")
        format_name = FORMAT_TO_PARSER.get(format_name, "generic")

    # Normalize name
    format_name = format_name.lower().strip()

    if format_name not in PARSER_REGISTRY:
        raise ValueError(
            f"Unknown format: {format_name}. Available formats: {', '.join(PARSER_REGISTRY.keys())}"
        )

    return PARSER_REGISTRY[format_name]()


def detect_format(
    file_path: str,
    sample_size: int = 100,
) -> tuple[BaseLogParser, float]:
    """
    Detect log format by analyzing sample lines.

    Reads first sample_size lines and scores each parser's confidence.
    Returns the best matching parser.

    Args:
        file_path: Path to log file
        sample_size: Number of lines to sample for detection

    Returns:
        Tuple of (parser_instance, confidence_score)
    """
    # Read sample lines
    sample_lines: list[str] = []
    for _, line in stream_file(file_path, max_lines=sample_size):
        sample_lines.append(line)

    if not sample_lines:
        # Empty file - return generic parser with low confidence
        return GenericParser(), 0.0

    return detect_format_from_lines(sample_lines)


def detect_format_from_lines(
    sample_lines: list[str],
) -> tuple[BaseLogParser, float]:
    """
    Detect log format from a list of sample lines.

    Args:
        sample_lines: List of log lines to analyze

    Returns:
        Tuple of (parser_instance, confidence_score)
    """
    if not sample_lines:
        return GenericParser(), 0.0

    best_parser: BaseLogParser | None = None
    best_confidence = 0.0

    # Test each parser in detection order
    for parser_name in DETECTION_ORDER:
        parser_class = PARSER_REGISTRY[parser_name]
        confidence = parser_class.detect_confidence(sample_lines)

        # Update best if this parser has higher confidence
        if confidence > best_confidence:
            best_confidence = confidence
            best_parser = parser_class()

            # Early exit if we have high confidence
            if confidence >= 0.9:
                break

    # Ensure we always return a parser
    if best_parser is None:
        return GenericParser(), 0.0

    return best_parser, best_confidence


def list_formats() -> list[dict[str, str]]:
    """
    List all available log formats.

    Returns:
        List of format info dictionaries
    """
    formats = []
    for name, parser_class in PARSER_REGISTRY.items():
        formats.append(
            {
                "name": name,
                "description": parser_class.description,
            }
        )
    return formats


def get_parser_for_format(log_format: LogFormat) -> BaseLogParser:
    """
    Get parser for a LogFormat enum value.

    Args:
        log_format: LogFormat enum value

    Returns:
        Instantiated parser

    Raises:
        ValueError: If format is AUTO (use detect_format instead)
    """
    if log_format == LogFormat.AUTO:
        raise ValueError("Use detect_format() for auto-detection")

    parser_name = FORMAT_TO_PARSER.get(log_format)
    if parser_name is None:
        return GenericParser()

    return PARSER_REGISTRY[parser_name]()


__all__ = [
    # Models
    "ParsedLogEntry",
    # Parser classes
    "BaseLogParser",
    "SyslogParser",
    "ApacheAccessParser",
    "ApacheErrorParser",
    "JSONLParser",
    "PythonLogParser",
    "JavaLogParser",
    "DockerParser",
    "KubernetesParser",
    "GenericParser",
    # Registry
    "PARSER_REGISTRY",
    "DETECTION_ORDER",
    # Functions
    "get_parser",
    "detect_format",
    "detect_format_from_lines",
    "list_formats",
    "get_parser_for_format",
]
