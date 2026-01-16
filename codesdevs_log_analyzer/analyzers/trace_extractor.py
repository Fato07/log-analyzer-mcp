"""Trace ID extractor - Extract and correlate trace/correlation IDs from logs."""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..parsers.base import ParsedLogEntry

# Common trace ID field names to look for in metadata
TRACE_ID_FIELDS = [
    "trace_id",
    "traceId",
    "traceid",
    "trace-id",
    "x-trace-id",
    "X-Trace-ID",
    "request_id",
    "requestId",
    "request-id",
    "x-request-id",
    "X-Request-ID",
    "correlation_id",
    "correlationId",
    "correlation-id",
    "x-correlation-id",
    "X-Correlation-ID",
    "span_id",
    "spanId",
    "span-id",
    "transaction_id",
    "transactionId",
    "txn_id",
    "session_id",
    "sessionId",
    "req_id",
    "reqId",
]

# Regex patterns for detecting trace IDs in message content
TRACE_ID_PATTERNS = [
    # UUID format (most common)
    (r"(?:trace[-_]?id|request[-_]?id|correlation[-_]?id|span[-_]?id)[=:\"'\s]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", "uuid"),
    # 32-char hex (OpenTelemetry trace ID)
    (r"(?:trace[-_]?id|traceId)[=:\"'\s]+([a-f0-9]{32})", "otel_trace"),
    # 16-char hex (OpenTelemetry span ID)
    (r"(?:span[-_]?id|spanId)[=:\"'\s]+([a-f0-9]{16})", "otel_span"),
    # Generic hex IDs (16-64 chars)
    (r"(?:request[-_]?id|req[-_]?id|correlation[-_]?id|txn[-_]?id)[=:\"'\s]+([a-f0-9]{16,64})", "hex_id"),
    # AWS X-Ray format
    (r"Root=(\d-[a-f0-9]{8}-[a-f0-9]{24})", "xray"),
    # Square bracket format [trace_id=xxx]
    (r"\[(?:trace[-_]?id|request[-_]?id|correlation[-_]?id)=([^\]]+)\]", "bracketed"),
    # Key=value format
    (r"(?:^|\s)(?:trace[-_]?id|request[-_]?id|correlation[-_]?id)=([a-zA-Z0-9_-]{8,64})(?:\s|$|,)", "key_value"),
]


@dataclass
class TraceEntry:
    """A single log entry with trace information."""

    entry: ParsedLogEntry
    trace_id: str
    trace_id_type: str  # uuid, otel_trace, otel_span, etc.
    span_id: str | None = None
    parent_span_id: str | None = None


@dataclass
class TraceGroup:
    """A group of log entries sharing the same trace ID."""

    trace_id: str
    trace_id_type: str
    entries: list[TraceEntry] = field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    levels: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    has_errors: bool = False
    error_count: int = 0

    @property
    def duration_ms(self) -> float | None:
        """Calculate trace duration in milliseconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds() * 1000
        return None

    @property
    def entry_count(self) -> int:
        """Number of entries in this trace."""
        return len(self.entries)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "trace_id": self.trace_id,
            "trace_id_type": self.trace_id_type,
            "entry_count": self.entry_count,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "levels": list(self.levels),
            "sources": list(self.sources),
            "has_errors": self.has_errors,
            "error_count": self.error_count,
            "entries": [
                {
                    "line_number": te.entry.line_number,
                    "timestamp": te.entry.timestamp.isoformat() if te.entry.timestamp else None,
                    "level": te.entry.level.value if te.entry.level else None,
                    "message": te.entry.message[:300],
                    "span_id": te.span_id,
                }
                for te in self.entries[:50]  # Limit entries in output
            ],
        }


@dataclass
class TraceExtractionResult:
    """Result of trace ID extraction."""

    total_entries: int = 0
    entries_with_traces: int = 0
    unique_trace_ids: int = 0
    trace_groups: list[TraceGroup] = field(default_factory=list)
    detected_trace_formats: dict[str, int] = field(default_factory=dict)
    broken_traces: list[str] = field(default_factory=list)  # Traces with gaps
    error_traces: list[str] = field(default_factory=list)  # Traces containing errors

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_entries": self.total_entries,
            "entries_with_traces": self.entries_with_traces,
            "unique_trace_ids": self.unique_trace_ids,
            "trace_coverage": round(self.entries_with_traces / self.total_entries * 100, 1)
            if self.total_entries > 0
            else 0,
            "detected_trace_formats": self.detected_trace_formats,
            "error_trace_count": len(self.error_traces),
            "trace_groups": [g.to_dict() for g in self.trace_groups],
        }


class TraceExtractor:
    """
    Extract and correlate trace/correlation IDs from log entries.

    Features:
    - Auto-detects trace ID formats (UUID, OpenTelemetry, AWS X-Ray, etc.)
    - Groups entries by trace ID
    - Identifies traces with errors
    - Calculates trace duration
    - Detects broken traces (missing spans)
    """

    ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL", "EMERGENCY", "SEVERE"}

    def __init__(
        self,
        trace_id: str | None = None,
        max_traces: int = 100,
        include_all_entries: bool = False,
    ):
        """
        Initialize trace extractor.

        Args:
            trace_id: Specific trace ID to filter for (None for all)
            max_traces: Maximum number of trace groups to return
            include_all_entries: If True, include all entries even without trace IDs
        """
        self.target_trace_id = trace_id.lower() if trace_id else None
        self.max_traces = max_traces
        self.include_all_entries = include_all_entries

        # Compile patterns
        self._patterns = [
            (re.compile(pattern, re.IGNORECASE), id_type)
            for pattern, id_type in TRACE_ID_PATTERNS
        ]

        # State
        self._trace_groups: dict[str, TraceGroup] = {}
        self._total_entries = 0
        self._entries_with_traces = 0
        self._format_counts: dict[str, int] = defaultdict(int)

    def _extract_trace_from_metadata(
        self, entry: ParsedLogEntry
    ) -> tuple[str | None, str | None, str]:
        """
        Extract trace ID from entry metadata.

        Returns:
            Tuple of (trace_id, span_id, trace_type)
        """
        metadata = entry.metadata
        trace_id = None
        span_id = None

        for field_name in TRACE_ID_FIELDS:
            if field_name in metadata:
                value = str(metadata[field_name]).strip()
                if value and len(value) >= 8:
                    # Determine type based on field name
                    if "span" in field_name.lower():
                        span_id = value.lower()
                    else:
                        trace_id = value.lower()

        if trace_id:
            # Determine trace type
            if len(trace_id) == 36 and trace_id.count("-") == 4:
                return trace_id, span_id, "uuid"
            elif len(trace_id) == 32:
                return trace_id, span_id, "otel_trace"
            elif len(trace_id) == 16:
                return trace_id, span_id, "otel_span"
            else:
                return trace_id, span_id, "custom"

        return None, span_id, "unknown"

    def _extract_trace_from_message(
        self, message: str
    ) -> tuple[str | None, str | None, str]:
        """
        Extract trace ID from message content using regex patterns.

        Returns:
            Tuple of (trace_id, span_id, trace_type)
        """
        trace_id = None
        span_id = None
        trace_type = "unknown"

        for pattern, id_type in self._patterns:
            match = pattern.search(message)
            if match:
                value = match.group(1).lower()
                if "span" in id_type:
                    span_id = value
                else:
                    trace_id = value
                    trace_type = id_type

        return trace_id, span_id, trace_type

    def _is_error(self, entry: ParsedLogEntry) -> bool:
        """Check if entry is an error level."""
        if not entry.level:
            return False
        level_str = entry.level.value if hasattr(entry.level, "value") else str(entry.level)
        return level_str.upper() in self.ERROR_LEVELS

    def _get_source(self, entry: ParsedLogEntry) -> str | None:
        """Extract source identifier from entry."""
        metadata = entry.metadata
        for key in ["service", "hostname", "host", "source", "process", "container", "pod", "app"]:
            if key in metadata:
                return str(metadata[key])
        return None

    def process_entry(self, entry: ParsedLogEntry) -> TraceEntry | None:
        """
        Process a single log entry and extract trace information.

        Args:
            entry: Parsed log entry

        Returns:
            TraceEntry if trace ID found, None otherwise
        """
        self._total_entries += 1

        # Try to extract trace ID from metadata first
        trace_id, span_id, trace_type = self._extract_trace_from_metadata(entry)

        # Fall back to message parsing
        if not trace_id:
            trace_id, msg_span_id, trace_type = self._extract_trace_from_message(
                entry.message
            )
            if msg_span_id and not span_id:
                span_id = msg_span_id

        # Also check raw line for trace IDs
        if not trace_id:
            trace_id, raw_span_id, trace_type = self._extract_trace_from_message(
                entry.raw_line
            )
            if raw_span_id and not span_id:
                span_id = raw_span_id

        if not trace_id:
            return None

        # Filter for specific trace ID if requested
        if self.target_trace_id and trace_id != self.target_trace_id:
            return None

        self._entries_with_traces += 1
        self._format_counts[trace_type] += 1

        # Create trace entry
        trace_entry = TraceEntry(
            entry=entry,
            trace_id=trace_id,
            trace_id_type=trace_type,
            span_id=span_id,
        )

        # Add to trace group
        if trace_id not in self._trace_groups:
            if len(self._trace_groups) >= self.max_traces and not self.target_trace_id:
                # Hit limit, just count but don't store
                return trace_entry

            self._trace_groups[trace_id] = TraceGroup(
                trace_id=trace_id,
                trace_id_type=trace_type,
            )

        group = self._trace_groups[trace_id]
        group.entries.append(trace_entry)

        # Update group metadata
        if entry.timestamp:
            if group.start_time is None or entry.timestamp < group.start_time:
                group.start_time = entry.timestamp
            if group.end_time is None or entry.timestamp > group.end_time:
                group.end_time = entry.timestamp

        if entry.level:
            level_str = entry.level.value if hasattr(entry.level, "value") else str(entry.level)
            group.levels.add(level_str)

        source = self._get_source(entry)
        if source:
            group.sources.add(source)

        if self._is_error(entry):
            group.has_errors = True
            group.error_count += 1

        return trace_entry

    def finalize(self) -> TraceExtractionResult:
        """
        Finalize extraction and return results.

        Returns:
            TraceExtractionResult with all trace groups
        """
        # Sort trace groups by entry count (most entries first)
        sorted_groups = sorted(
            self._trace_groups.values(),
            key=lambda g: g.entry_count,
            reverse=True,
        )

        # Sort entries within each group by timestamp
        for group in sorted_groups:
            group.entries.sort(
                key=lambda te: te.entry.timestamp or datetime.min
            )

        # Identify error traces
        error_traces = [g.trace_id for g in sorted_groups if g.has_errors]

        return TraceExtractionResult(
            total_entries=self._total_entries,
            entries_with_traces=self._entries_with_traces,
            unique_trace_ids=len(self._trace_groups),
            trace_groups=sorted_groups,
            detected_trace_formats=dict(self._format_counts),
            error_traces=error_traces,
        )

    def analyze_file(
        self,
        parser: Any,
        file_path: str,
        max_lines: int = 10000,
    ) -> TraceExtractionResult:
        """
        Extract trace IDs from a log file.

        Args:
            parser: Log parser to use
            file_path: Path to log file
            max_lines: Maximum lines to process

        Returns:
            TraceExtractionResult with all trace groups
        """
        for entry in parser.parse_file(file_path, max_lines=max_lines):
            self.process_entry(entry)
        return self.finalize()


def extract_traces(
    parser: Any,
    file_path: str,
    trace_id: str | None = None,
    max_traces: int = 100,
    max_lines: int = 10000,
) -> TraceExtractionResult:
    """
    Convenience function to extract traces from a log file.

    Args:
        parser: Log parser to use
        file_path: Path to log file
        trace_id: Specific trace ID to filter for (None for all)
        max_traces: Maximum trace groups to return
        max_lines: Maximum lines to process

    Returns:
        TraceExtractionResult with all trace groups
    """
    extractor = TraceExtractor(
        trace_id=trace_id,
        max_traces=max_traces,
    )
    return extractor.analyze_file(parser, file_path, max_lines=max_lines)
