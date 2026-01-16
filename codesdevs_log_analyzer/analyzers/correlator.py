"""Correlator analyzer - Correlate events around anchor points."""

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..parsers.base import BaseLogParser, ParsedLogEntry
from .recommendation_engine import CausalChain, RecommendationEngine

# Output limits
MAX_ANCHORS = 10
MAX_EVENTS_PER_WINDOW = 100
MAX_PRECURSORS = 10


@dataclass
class CorrelationWindow:
    """A time window around an anchor event."""

    anchor_entry: ParsedLogEntry
    events_before: list[ParsedLogEntry] = field(default_factory=list)
    events_after: list[ParsedLogEntry] = field(default_factory=list)
    related_errors: list[ParsedLogEntry] = field(default_factory=list)
    unique_sources: list[str] = field(default_factory=list)
    causal_chain: CausalChain | None = None  # Causal chain analysis

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {
            "anchor": {
                "line_number": self.anchor_entry.line_number,
                "timestamp": self.anchor_entry.timestamp.isoformat()
                if self.anchor_entry.timestamp
                else None,
                "level": self.anchor_entry.level,
                "message": self.anchor_entry.message[:500],
            },
            "events_before": [
                {
                    "line_number": e.line_number,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "level": e.level,
                    "message": e.message[:200],
                }
                for e in self.events_before[:MAX_EVENTS_PER_WINDOW]
            ],
            "events_after": [
                {
                    "line_number": e.line_number,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "level": e.level,
                    "message": e.message[:200],
                }
                for e in self.events_after[:MAX_EVENTS_PER_WINDOW]
            ],
            "related_errors": [
                {
                    "line_number": e.line_number,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "level": e.level,
                    "message": e.message[:200],
                }
                for e in self.related_errors
            ],
            "unique_sources": self.unique_sources,
            "event_counts": {
                "before": len(self.events_before),
                "after": len(self.events_after),
                "errors": len(self.related_errors),
            },
        }

        # Add causal chain if present
        if self.causal_chain:
            result["causal_analysis"] = self.causal_chain.to_dict()

        return result


@dataclass
class CorrelationResult:
    """Result of event correlation."""

    anchor_pattern: str
    total_anchors: int = 0
    windows: list[CorrelationWindow] = field(default_factory=list)
    common_precursors: list[str] = field(default_factory=list)
    truncated: bool = False
    # Causal analysis aggregates
    recommendations: list[str] = field(default_factory=list)
    root_cause_summary: str | None = None
    causal_chain_detected: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {
            "anchor_pattern": self.anchor_pattern,
            "total_anchors": self.total_anchors,
            "windows": [w.to_dict() for w in self.windows],
            "common_precursors": self.common_precursors,
            "truncated": self.truncated,
        }

        # Add causal analysis summary if detected
        if self.causal_chain_detected:
            result["causal_analysis_summary"] = {
                "root_cause_summary": self.root_cause_summary,
                "recommendations": self.recommendations,
                "chains_detected": sum(
                    1 for w in self.windows if w.causal_chain is not None
                ),
            }

        return result


class Correlator:
    """
    Event correlator that finds events around anchor points.

    Two-pass algorithm:
    1. First pass: Find all anchor points
    2. Second pass: Collect events in time windows around anchors

    Features:
    - Pattern-based anchor detection
    - Time-window correlation
    - Causal chain detection (optional)
    - Actionable recommendations
    """

    # Error levels for related error detection
    ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL", "EMERGENCY", "SEVERE"}

    def __init__(
        self,
        anchor_pattern: str,
        window_before: int = 60,
        window_after: int = 30,
        max_anchors: int = MAX_ANCHORS,
        regex: bool = True,
        case_sensitive: bool = False,
        detect_causal_chain: bool = True,
        include_recommendations: bool = True,
    ):
        """
        Initialize correlator.

        Args:
            anchor_pattern: Pattern to find anchor events
            window_before: Seconds before anchor to analyze
            window_after: Seconds after anchor to analyze
            max_anchors: Maximum anchor events to analyze
            regex: Treat pattern as regex
            case_sensitive: Case-sensitive pattern matching
            detect_causal_chain: Enable causal chain detection
            include_recommendations: Include actionable recommendations
        """
        self.anchor_pattern_str = anchor_pattern
        self.window_before = timedelta(seconds=window_before)
        self.window_after = timedelta(seconds=window_after)
        self.max_anchors = min(max_anchors, MAX_ANCHORS)
        self.regex = regex
        self.case_sensitive = case_sensitive
        self.detect_causal_chain = detect_causal_chain
        self.include_recommendations = include_recommendations

        # Initialize recommendation engine if needed
        self._recommendation_engine: RecommendationEngine | None = None
        if detect_causal_chain or include_recommendations:
            self._recommendation_engine = RecommendationEngine()

        # Compile pattern
        flags = 0 if case_sensitive else re.IGNORECASE
        if regex:
            try:
                self._pattern = re.compile(anchor_pattern, flags)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}") from e
        else:
            escaped = re.escape(anchor_pattern)
            self._pattern = re.compile(escaped, flags)

        # State for first pass
        self._anchors: list[ParsedLogEntry] = []
        self._all_entries: list[ParsedLogEntry] = []  # For correlation
        self._total_anchors = 0

    def _is_anchor(self, entry: ParsedLogEntry) -> bool:
        """Check if entry matches anchor pattern."""
        return bool(self._pattern.search(entry.message) or self._pattern.search(entry.raw_line))

    def _is_error(self, entry: ParsedLogEntry) -> bool:
        """Check if entry is an error."""
        if not entry.level:
            return False
        return entry.level.upper() in self.ERROR_LEVELS

    def _get_source(self, entry: ParsedLogEntry) -> str | None:
        """Extract source identifier from entry."""
        # Try common metadata fields
        metadata = entry.metadata
        for key in ["hostname", "host", "source", "process", "service", "container", "pod"]:
            if key in metadata:
                return str(metadata[key])

        # Try to extract from message
        # Look for common patterns like "hostname:" or "[service]"
        match = re.search(r"^(\S+):", entry.message)
        if match:
            return match.group(1)

        return None

    def _normalize_message(self, message: str) -> str:
        """Normalize message for precursor grouping."""
        # Replace numbers with <N>
        result = re.sub(r"\b\d+\b", "<N>", message)
        # Collapse whitespace
        result = re.sub(r"\s+", " ", result)
        # Truncate
        if len(result) > 100:
            result = result[:100] + "..."
        return result.strip()

    def process_entry(self, entry: ParsedLogEntry) -> None:
        """
        Process a single log entry (first pass).

        Args:
            entry: Parsed log entry
        """
        # Store all entries for second pass
        self._all_entries.append(entry)

        # Check if this is an anchor
        if self._is_anchor(entry):
            self._total_anchors += 1
            if len(self._anchors) < self.max_anchors:
                self._anchors.append(entry)

    def _build_window(self, anchor: ParsedLogEntry) -> CorrelationWindow:
        """Build correlation window around an anchor."""
        window = CorrelationWindow(anchor_entry=anchor)

        if anchor.timestamp is None:
            # Can't correlate by time without timestamp
            return window

        time_start = anchor.timestamp - self.window_before
        time_end = anchor.timestamp + self.window_after

        sources: set[str] = set()

        for entry in self._all_entries:
            if entry.line_number == anchor.line_number:
                continue  # Skip anchor itself

            if entry.timestamp is None:
                continue

            # Check if in time window
            if time_start <= entry.timestamp <= time_end:
                # Track source
                source = self._get_source(entry)
                if source:
                    sources.add(source)

                # Categorize entry
                if entry.timestamp < anchor.timestamp:
                    if len(window.events_before) < MAX_EVENTS_PER_WINDOW:
                        window.events_before.append(entry)
                else:
                    if len(window.events_after) < MAX_EVENTS_PER_WINDOW:
                        window.events_after.append(entry)

                # Track related errors
                if self._is_error(entry):
                    window.related_errors.append(entry)

        # Sort events by timestamp
        window.events_before.sort(key=lambda e: e.timestamp or datetime.min)
        window.events_after.sort(key=lambda e: e.timestamp or datetime.min)

        window.unique_sources = list(sources)

        # Build causal chain if enabled
        if self.detect_causal_chain and self._recommendation_engine:
            window.causal_chain = self._recommendation_engine.build_causal_chain(
                anchor=anchor,
                events_before=window.events_before,
            )

        return window

    def _find_common_precursors(self, windows: list[CorrelationWindow]) -> list[str]:
        """Find events that commonly appear before anchors."""
        precursor_counts: Counter[str] = Counter()

        for window in windows:
            seen_in_window: set[str] = set()
            for entry in window.events_before:
                normalized = self._normalize_message(entry.message)
                if normalized not in seen_in_window:
                    seen_in_window.add(normalized)
                    precursor_counts[normalized] += 1

        # Return precursors that appear in >50% of windows
        threshold = len(windows) * 0.5
        common = [
            msg
            for msg, count in precursor_counts.most_common(MAX_PRECURSORS * 2)
            if count >= threshold
        ]

        return common[:MAX_PRECURSORS]

    def finalize(self) -> CorrelationResult:
        """
        Finalize correlation and return results.

        Returns:
            CorrelationResult with all correlation windows
        """
        # Build windows for each anchor
        windows = [self._build_window(anchor) for anchor in self._anchors]

        # Find common precursors
        common_precursors = self._find_common_precursors(windows)

        # Aggregate causal chain results
        recommendations: list[str] = []
        root_cause_hypotheses: list[str] = []
        causal_chain_detected = False

        for window in windows:
            if window.causal_chain:
                causal_chain_detected = True
                if window.causal_chain.root_cause_hypothesis:
                    root_cause_hypotheses.append(window.causal_chain.root_cause_hypothesis)
                for rec in window.causal_chain.recommendations:
                    if rec not in recommendations:
                        recommendations.append(rec)

        # Generate root cause summary
        root_cause_summary: str | None = None
        if root_cause_hypotheses:
            # Count unique hypotheses and pick most common
            hypothesis_counts: Counter[str] = Counter(root_cause_hypotheses)
            most_common = hypothesis_counts.most_common(1)
            if most_common:
                root_cause_summary = most_common[0][0]

        return CorrelationResult(
            anchor_pattern=self.anchor_pattern_str,
            total_anchors=self._total_anchors,
            windows=windows,
            common_precursors=common_precursors,
            truncated=self._total_anchors > len(windows),
            recommendations=recommendations[:10],  # Limit to top 10
            root_cause_summary=root_cause_summary,
            causal_chain_detected=causal_chain_detected,
        )

    def correlate_file(
        self, parser: BaseLogParser, file_path: str, max_lines: int = 10000
    ) -> CorrelationResult:
        """
        Correlate events in a log file.

        Args:
            parser: Parser to use for parsing log entries
            file_path: Path to the log file
            max_lines: Maximum lines to process

        Returns:
            CorrelationResult with all correlation windows
        """
        for entry in parser.parse_file(file_path, max_lines=max_lines):
            self.process_entry(entry)
        return self.finalize()

    def correlate_entries(self, entries: Iterator[ParsedLogEntry]) -> CorrelationResult:
        """
        Correlate events from an iterator of entries.

        Args:
            entries: Iterator of parsed log entries

        Returns:
            CorrelationResult with all correlation windows
        """
        for entry in entries:
            self.process_entry(entry)
        return self.finalize()


class StreamingCorrelator:
    """
    Memory-efficient streaming correlator.
    Uses sliding window instead of storing all entries.
    Suitable for very large files where the standard Correlator would use too much memory.
    """

    ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL", "EMERGENCY", "SEVERE"}

    def __init__(
        self,
        anchor_pattern: str,
        window_before: int = 60,
        window_after: int = 30,
        max_anchors: int = MAX_ANCHORS,
        regex: bool = True,
        case_sensitive: bool = False,
    ):
        """
        Initialize streaming correlator.

        Args:
            anchor_pattern: Pattern to find anchor events
            window_before: Seconds before anchor to analyze
            window_after: Seconds after anchor to analyze
            max_anchors: Maximum anchor events to analyze
            regex: Treat pattern as regex
            case_sensitive: Case-sensitive pattern matching
        """
        self.anchor_pattern_str = anchor_pattern
        self.window_before_secs = window_before
        self.window_after_secs = window_after
        self.max_anchors = min(max_anchors, MAX_ANCHORS)

        # Compile pattern
        flags = 0 if case_sensitive else re.IGNORECASE
        if regex:
            try:
                self._pattern = re.compile(anchor_pattern, flags)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}") from e
        else:
            escaped = re.escape(anchor_pattern)
            self._pattern = re.compile(escaped, flags)

        # State
        self._total_anchors = 0
        self._windows: list[CorrelationWindow] = []

        # Sliding window buffer (entries within window_before seconds)
        self._buffer: list[ParsedLogEntry] = []
        self._buffer_start_time: datetime | None = None

        # Pending anchors waiting for after-events
        self._pending_anchors: list[tuple[CorrelationWindow, datetime]] = []  # (window, deadline)

    def _is_anchor(self, entry: ParsedLogEntry) -> bool:
        """Check if entry matches anchor pattern."""
        return bool(self._pattern.search(entry.message) or self._pattern.search(entry.raw_line))

    def _is_error(self, entry: ParsedLogEntry) -> bool:
        """Check if entry is an error."""
        if not entry.level:
            return False
        return entry.level.upper() in self.ERROR_LEVELS

    def _prune_buffer(self, current_time: datetime) -> None:
        """Remove old entries from buffer."""
        cutoff = current_time - timedelta(seconds=self.window_before_secs)
        self._buffer = [e for e in self._buffer if e.timestamp and e.timestamp >= cutoff]

    def _finalize_pending(self, current_time: datetime | None) -> None:
        """Finalize pending anchors whose after-window has expired."""
        if current_time is None:
            # Finalize all pending
            for window, _ in self._pending_anchors:
                if len(self._windows) < self.max_anchors:
                    self._windows.append(window)
            self._pending_anchors = []
            return

        still_pending = []
        for window, deadline in self._pending_anchors:
            if current_time > deadline:
                # Window complete
                if len(self._windows) < self.max_anchors:
                    self._windows.append(window)
            else:
                still_pending.append((window, deadline))
        self._pending_anchors = still_pending

    def process_entry(self, entry: ParsedLogEntry) -> None:
        """
        Process a single log entry.

        Args:
            entry: Parsed log entry
        """
        current_time = entry.timestamp

        if current_time:
            # Prune old entries from buffer
            self._prune_buffer(current_time)

            # Finalize expired pending anchors
            self._finalize_pending(current_time)

            # Add to pending anchor windows (after-events)
            for window, deadline in self._pending_anchors:
                if current_time <= deadline:
                    if len(window.events_after) < MAX_EVENTS_PER_WINDOW:
                        window.events_after.append(entry)
                    if self._is_error(entry):
                        window.related_errors.append(entry)

        # Check if this is an anchor
        if self._is_anchor(entry):
            self._total_anchors += 1

            if len(self._windows) + len(self._pending_anchors) < self.max_anchors:
                # Create new window with buffer contents as before-events
                window = CorrelationWindow(
                    anchor_entry=entry,
                    events_before=list(self._buffer),
                    events_after=[],
                    related_errors=[e for e in self._buffer if self._is_error(e)],
                )

                if current_time:
                    deadline = current_time + timedelta(seconds=self.window_after_secs)
                    self._pending_anchors.append((window, deadline))
                else:
                    # No timestamp, can't collect after-events
                    self._windows.append(window)

        # Add to buffer for future anchor before-events
        if current_time:
            self._buffer.append(entry)

    def finalize(self) -> CorrelationResult:
        """
        Finalize correlation and return results.

        Returns:
            CorrelationResult with all correlation windows
        """
        # Finalize all remaining pending anchors
        self._finalize_pending(None)

        return CorrelationResult(
            anchor_pattern=self.anchor_pattern_str,
            total_anchors=self._total_anchors,
            windows=self._windows,
            common_precursors=[],  # Not tracked in streaming mode
            truncated=self._total_anchors > len(self._windows),
        )

    def correlate_file(
        self, parser: BaseLogParser, file_path: str, max_lines: int = 10000
    ) -> CorrelationResult:
        """
        Correlate events in a log file using streaming mode.

        Args:
            parser: Parser to use for parsing log entries
            file_path: Path to the log file
            max_lines: Maximum lines to process

        Returns:
            CorrelationResult with all correlation windows
        """
        for entry in parser.parse_file(file_path, max_lines=max_lines):
            self.process_entry(entry)
        return self.finalize()

    def correlate_entries(self, entries: Iterator[ParsedLogEntry]) -> CorrelationResult:
        """
        Correlate events from an iterator of entries.

        Args:
            entries: Iterator of parsed log entries

        Returns:
            CorrelationResult with all correlation windows
        """
        for entry in entries:
            self.process_entry(entry)
        return self.finalize()


def correlate_events(
    parser: BaseLogParser,
    file_path: str,
    anchor_pattern: str,
    window_before: int = 60,
    window_after: int = 30,
    max_anchors: int = MAX_ANCHORS,
    regex: bool = True,
    case_sensitive: bool = False,
    max_lines: int = 10000,
    streaming: bool = False,
    detect_causal_chain: bool = True,
    include_recommendations: bool = True,
) -> CorrelationResult:
    """
    Convenience function to correlate events in a log file.

    Args:
        parser: Parser to use for parsing log entries
        file_path: Path to the log file
        anchor_pattern: Pattern to find anchor events
        window_before: Seconds before anchor to analyze
        window_after: Seconds after anchor to analyze
        max_anchors: Maximum anchor events to analyze
        regex: Treat pattern as regex
        case_sensitive: Case-sensitive pattern matching
        max_lines: Maximum lines to process
        streaming: Use memory-efficient streaming mode
        detect_causal_chain: Enable causal chain detection
        include_recommendations: Include actionable recommendations

    Returns:
        CorrelationResult with all correlation windows
    """
    if streaming:
        # StreamingCorrelator doesn't support causal chains (yet)
        correlator: Correlator | StreamingCorrelator = StreamingCorrelator(
            anchor_pattern=anchor_pattern,
            window_before=window_before,
            window_after=window_after,
            max_anchors=max_anchors,
            regex=regex,
            case_sensitive=case_sensitive,
        )
    else:
        correlator = Correlator(
            anchor_pattern=anchor_pattern,
            window_before=window_before,
            window_after=window_after,
            max_anchors=max_anchors,
            regex=regex,
            case_sensitive=case_sensitive,
            detect_causal_chain=detect_causal_chain,
            include_recommendations=include_recommendations,
        )

    return correlator.correlate_file(parser, file_path, max_lines=max_lines)
