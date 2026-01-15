"""Base log parser abstract class."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Iterator, Optional

from pydantic import BaseModel, Field


class ParsedLogEntry(BaseModel):
    """A single parsed log entry."""
    line_number: int = Field(..., description="Line number in the source file")
    raw_line: str = Field(..., description="Original unparsed line")
    timestamp: Optional[datetime] = Field(None, description="Parsed timestamp")
    level: Optional[str] = Field(None, description="Log level (ERROR, WARN, INFO, etc.)")
    message: str = Field(..., description="Log message content")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Parser-specific fields (hostname, pid, etc.)"
    )

    class Config:
        """Pydantic config."""
        extra = "allow"


class BaseLogParser(ABC):
    """Abstract base class for all log parsers."""

    name: str = "base"
    patterns: list[str] = []  # Regex patterns this parser handles

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Check if this parser can handle the line."""
        pass

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        """Parse a single log line."""
        pass

    def parse_file(
        self,
        file_path: str,
        max_lines: int = 10000,
        encoding: str = "utf-8"
    ) -> Iterator[ParsedLogEntry]:
        """
        Stream parse a file.

        Args:
            file_path: Path to the log file
            max_lines: Maximum number of lines to process
            encoding: File encoding

        Yields:
            ParsedLogEntry for each successfully parsed line
        """
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                for line_number, line in enumerate(f, start=1):
                    if line_number > max_lines:
                        break

                    line = line.rstrip('\n\r')
                    if not line:
                        continue

                    try:
                        entry = self.parse_line(line, line_number)
                        if entry is not None:
                            yield entry
                    except Exception:
                        # Skip malformed lines
                        continue
        except Exception:
            return

    @classmethod
    def detect_confidence(cls, sample_lines: list[str]) -> float:
        """
        Return 0.0-1.0 confidence score for format detection.

        Args:
            sample_lines: Sample of lines from the log file

        Returns:
            Confidence score between 0.0 and 1.0
        """
        if not sample_lines:
            return 0.0

        parser = cls()
        parseable = 0

        for line in sample_lines:
            if line.strip() and parser.can_parse(line):
                parseable += 1

        return parseable / len(sample_lines) if sample_lines else 0.0
