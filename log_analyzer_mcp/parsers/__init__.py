"""Log parser registry and auto-detection."""

from typing import Callable

from .base import BaseLogParser, ParsedLogEntry

# Parser registry - will be populated by parser implementations
PARSER_REGISTRY: dict[str, type[BaseLogParser]] = {}


def register_parser(name: str) -> Callable[[type[BaseLogParser]], type[BaseLogParser]]:
    """Decorator to register a parser."""
    def decorator(cls: type[BaseLogParser]) -> type[BaseLogParser]:
        PARSER_REGISTRY[name] = cls
        return cls
    return decorator


def detect_format(file_path: str, sample_size: int = 100) -> tuple[BaseLogParser, float]:
    """
    Read first sample_size lines and return best parser with confidence score.

    Args:
        file_path: Path to log file
        sample_size: Number of lines to sample for detection

    Returns:
        Tuple of (parser_instance, confidence_score)
    """
    # Read sample lines
    sample_lines: list[str] = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= sample_size:
                    break
                sample_lines.append(line.rstrip('\n\r'))
    except Exception:
        sample_lines = []

    if not sample_lines:
        # Return generic parser with low confidence
        from .generic import GenericParser
        return GenericParser(), 0.1

    best_parser: BaseLogParser | None = None
    best_confidence = 0.0

    for parser_cls in PARSER_REGISTRY.values():
        try:
            confidence = parser_cls.detect_confidence(sample_lines)
            if confidence > best_confidence:
                best_confidence = confidence
                best_parser = parser_cls()
        except Exception:
            continue

    if best_parser is None:
        from .generic import GenericParser
        return GenericParser(), 0.1

    return best_parser, best_confidence


def get_parser(format_name: str) -> BaseLogParser:
    """Get parser by name."""
    if format_name not in PARSER_REGISTRY:
        from .generic import GenericParser
        return GenericParser()
    return PARSER_REGISTRY[format_name]()


__all__ = [
    "BaseLogParser",
    "ParsedLogEntry",
    "PARSER_REGISTRY",
    "register_parser",
    "detect_format",
    "get_parser",
]
