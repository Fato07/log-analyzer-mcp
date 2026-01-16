"""Multi-file analyzer - Analyze and correlate logs across multiple files."""

import heapq
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..parsers import detect_format
from ..parsers.base import BaseLogParser, ParsedLogEntry


@dataclass
class MultiFileEntry:
    """A log entry with source file information."""

    entry: ParsedLogEntry
    source_file: str
    file_index: int  # For stable sorting

    def __lt__(self, other: "MultiFileEntry") -> bool:
        """Compare by timestamp for heap operations."""
        if self.entry.timestamp is None:
            return False
        if other.entry.timestamp is None:
            return True
        if self.entry.timestamp == other.entry.timestamp:
            # Stable sort by file index, then line number
            if self.file_index != other.file_index:
                return self.file_index < other.file_index
            return self.entry.line_number < other.entry.line_number
        return self.entry.timestamp < other.entry.timestamp

    # Expose underlying entry fields for convenience
    @property
    def line_number(self) -> int:
        """Line number from the underlying entry."""
        return self.entry.line_number

    @property
    def timestamp(self) -> datetime | None:
        """Timestamp from the underlying entry."""
        return self.entry.timestamp

    @property
    def level(self) -> str | None:
        """Log level from the underlying entry."""
        if self.entry.level:
            return self.entry.level.value if hasattr(self.entry.level, "value") else str(self.entry.level)
        return None

    @property
    def message(self) -> str:
        """Message from the underlying entry."""
        return self.entry.message


@dataclass
class CorrelationCluster:
    """A cluster of correlated events from multiple files."""

    start_time: datetime
    end_time: datetime
    entries: list[MultiFileEntry] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    levels: dict[str, int] = field(default_factory=dict)
    error_count: int = 0
    summary: str = ""
    cluster_id: int = 0  # Set during finalization

    @property
    def duration_ms(self) -> float:
        """Duration of the cluster in milliseconds."""
        return (self.end_time - self.start_time).total_seconds() * 1000

    @property
    def files_involved(self) -> set[str]:
        """Alias for sources for compatibility."""
        return self.sources

    @property
    def entry_count(self) -> int:
        """Number of entries in this cluster."""
        return len(self.entries)

    @property
    def has_errors(self) -> bool:
        """Whether this cluster contains errors."""
        return self.error_count > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_ms": self.duration_ms,
            "entry_count": len(self.entries),
            "sources": list(self.sources),
            "levels": self.levels,
            "error_count": self.error_count,
            "summary": self.summary,
            "entries": [
                {
                    "source": e.source_file,
                    "line_number": e.entry.line_number,
                    "timestamp": e.entry.timestamp.isoformat() if e.entry.timestamp else None,
                    "level": e.entry.level.value if e.entry.level else None,
                    "message": e.entry.message[:200],
                }
                for e in self.entries[:50]
            ],
        }


@dataclass
class MultiFileResult:
    """Result of multi-file analysis."""

    operation: str  # "merge", "correlate", "compare"
    files: list[str]
    total_entries: int = 0
    entries_per_file: dict[str, int] = field(default_factory=dict)
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    files_info: dict[str, dict[str, Any]] = field(default_factory=dict)

    # For merge operation
    merged_entries: list[MultiFileEntry] = field(default_factory=list)

    # For correlate operation
    correlation_clusters: list[CorrelationCluster] = field(default_factory=list)

    # For compare operation
    file_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    common_errors: list[str] = field(default_factory=list)
    unique_errors: dict[str, list[str]] = field(default_factory=dict)

    @property
    def time_range(self) -> tuple[datetime | None, datetime | None]:
        """Return time range as a tuple for compatibility."""
        return (self.time_range_start, self.time_range_end)

    @property
    def comparison(self) -> dict[str, Any]:
        """Return comparison data as a dictionary for compatibility."""
        level_dist: dict[str, dict[str, int]] = {}
        for fp, summary in self.file_summaries.items():
            if "level_distribution" in summary:
                level_dist[fp] = summary["level_distribution"]

        # Build common_errors as dict with counts
        common_errors_dict: dict[str, dict[str, int]] = {}
        for err in self.common_errors:
            common_errors_dict[err] = {}
            for fp, _summary in self.file_summaries.items():
                # For now just mark as 1 if present
                common_errors_dict[err][fp] = 1

        return {
            "common_errors": common_errors_dict,
            "unique_errors": self.unique_errors,
            "level_distribution": level_dist,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: dict[str, Any] = {
            "operation": self.operation,
            "files": self.files,
            "total_entries": self.total_entries,
            "entries_per_file": self.entries_per_file,
            "time_range": {
                "start": self.time_range_start.isoformat() if self.time_range_start else None,
                "end": self.time_range_end.isoformat() if self.time_range_end else None,
            },
        }

        if self.operation == "merge":
            result["merged_entries"] = [
                {
                    "source": e.source_file,
                    "line_number": e.entry.line_number,
                    "timestamp": e.entry.timestamp.isoformat() if e.entry.timestamp else None,
                    "level": e.entry.level.value if e.entry.level else None,
                    "message": e.entry.message[:300],
                }
                for e in self.merged_entries
            ]
        elif self.operation == "correlate":
            result["cluster_count"] = len(self.correlation_clusters)
            result["clusters"] = [c.to_dict() for c in self.correlation_clusters]
        elif self.operation == "compare":
            result["file_summaries"] = self.file_summaries
            result["common_errors"] = self.common_errors
            result["unique_errors"] = self.unique_errors

        return result


class MultiFileAnalyzer:
    """
    Analyzer for multiple log files.

    Supports:
    - Merge: Interleave entries by timestamp (like 'sort -m')
    - Correlate: Find events happening across files within time windows
    - Compare: Diff error patterns between files
    """

    ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL", "EMERGENCY", "SEVERE"}
    WARN_LEVELS = {"WARN", "WARNING"}

    def __init__(
        self,
        time_window: int = 60,
        max_entries: int = 1000,
        max_clusters: int = 50,
    ):
        """
        Initialize multi-file analyzer.

        Args:
            time_window: Time window in seconds for correlation
            max_entries: Maximum entries to return in merge results
            max_clusters: Maximum clusters in correlation results
        """
        self.time_window = timedelta(seconds=time_window)
        self.max_entries = max_entries
        self.max_clusters = max_clusters

    def _get_parser(self, file_path: str) -> BaseLogParser:
        """Get the best parser for a file."""
        parser, _ = detect_format(file_path)
        return parser

    def _is_error(self, entry: ParsedLogEntry) -> bool:
        """Check if entry is an error."""
        if not entry.level:
            return False
        level_str = entry.level.value if hasattr(entry.level, "value") else str(entry.level)
        return level_str.upper() in self.ERROR_LEVELS

    def _normalize_error(self, message: str) -> str:
        """Normalize error message for comparison."""
        import re

        # Replace common variable patterns
        result = message
        result = re.sub(r"\b\d+\b", "<N>", result)  # Numbers
        result = re.sub(r"0x[a-fA-F0-9]+", "<HEX>", result)  # Hex
        result = re.sub(
            r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
            "<UUID>",
            result,
            flags=re.IGNORECASE,
        )
        result = re.sub(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>", result)
        result = re.sub(r"\s+", " ", result).strip()

        # Truncate
        if len(result) > 100:
            result = result[:100]

        return result

    def merge_files(
        self,
        file_paths: list[str],
        max_lines_per_file: int = 10000,
    ) -> MultiFileResult:
        """
        Merge multiple log files by timestamp.

        Args:
            file_paths: List of log file paths
            max_lines_per_file: Maximum lines to read from each file

        Returns:
            MultiFileResult with merged entries sorted by timestamp
        """
        result = MultiFileResult(
            operation="merge",
            files=file_paths,
        )

        # Create iterators for each file
        iterators: list[tuple[Iterator[MultiFileEntry], str, int]] = []

        for idx, file_path in enumerate(file_paths):
            parser = self._get_parser(file_path)

            def entry_generator(
                fp: str = file_path,
                p: BaseLogParser = parser,
                i: int = idx,
            ) -> Iterator[MultiFileEntry]:
                for entry in p.parse_file(fp, max_lines=max_lines_per_file):
                    yield MultiFileEntry(entry=entry, source_file=fp, file_index=i)

            iterators.append((entry_generator(), file_path, idx))

        # Use heap to merge sorted streams
        heap: list[tuple[datetime, int, int, MultiFileEntry]] = []
        entry_counts: dict[str, int] = defaultdict(int)

        # Initialize heap with first entry from each file
        for iterator, file_path, idx in iterators:
            try:
                entry = next(iterator)
                entry_counts[file_path] += 1
                if entry.entry.timestamp:
                    heapq.heappush(
                        heap,
                        (entry.entry.timestamp, idx, entry.entry.line_number, entry),
                    )
                else:
                    # No timestamp, add to results but can't sort properly
                    if len(result.merged_entries) < self.max_entries:
                        result.merged_entries.append(entry)
            except StopIteration:
                pass

        # Merge using heap
        file_iterators = {idx: (iterator, file_path) for iterator, file_path, idx in iterators}

        while heap and len(result.merged_entries) < self.max_entries:
            ts, idx, _, entry = heapq.heappop(heap)
            result.merged_entries.append(entry)

            # Update time range
            if result.time_range_start is None or ts < result.time_range_start:
                result.time_range_start = ts
            if result.time_range_end is None or ts > result.time_range_end:
                result.time_range_end = ts

            # Get next entry from same file
            if idx in file_iterators:
                iterator, file_path = file_iterators[idx]
                try:
                    next_entry = next(iterator)
                    entry_counts[file_path] += 1
                    if next_entry.entry.timestamp:
                        heapq.heappush(
                            heap,
                            (
                                next_entry.entry.timestamp,
                                idx,
                                next_entry.entry.line_number,
                                next_entry,
                            ),
                        )
                except StopIteration:
                    del file_iterators[idx]

        result.entries_per_file = dict(entry_counts)
        result.total_entries = sum(entry_counts.values())

        return result

    def correlate_files(
        self,
        file_paths: list[str],
        max_lines_per_file: int = 10000,
    ) -> MultiFileResult:
        """
        Find correlated events across multiple files within time windows.

        Args:
            file_paths: List of log file paths
            max_lines_per_file: Maximum lines to read from each file

        Returns:
            MultiFileResult with correlation clusters
        """
        result = MultiFileResult(
            operation="correlate",
            files=file_paths,
        )

        # Collect all entries with timestamps
        all_entries: list[MultiFileEntry] = []
        entry_counts: dict[str, int] = defaultdict(int)

        for idx, file_path in enumerate(file_paths):
            parser = self._get_parser(file_path)
            for entry in parser.parse_file(file_path, max_lines=max_lines_per_file):
                if entry.timestamp:  # Only include entries with timestamps
                    all_entries.append(
                        MultiFileEntry(entry=entry, source_file=file_path, file_index=idx)
                    )
                entry_counts[file_path] += 1

        # Sort by timestamp
        all_entries.sort(key=lambda e: e.entry.timestamp or datetime.min)

        # Build correlation clusters
        clusters: list[CorrelationCluster] = []
        current_cluster: CorrelationCluster | None = None

        for mf_entry in all_entries:
            if mf_entry.entry.timestamp is None:
                continue

            ts = mf_entry.entry.timestamp

            # Update time range
            if result.time_range_start is None or ts < result.time_range_start:
                result.time_range_start = ts
            if result.time_range_end is None or ts > result.time_range_end:
                result.time_range_end = ts

            # Check if entry belongs to current cluster
            if current_cluster is None:
                current_cluster = CorrelationCluster(
                    start_time=ts,
                    end_time=ts,
                )
            elif ts - current_cluster.end_time > self.time_window:
                # Gap too large, finalize current cluster and start new one
                if len(current_cluster.entries) > 1 and len(current_cluster.sources) > 1:
                    # Only keep clusters with events from multiple files
                    current_cluster.cluster_id = len(clusters) + 1
                    self._finalize_cluster(current_cluster)
                    if len(clusters) < self.max_clusters:
                        clusters.append(current_cluster)

                current_cluster = CorrelationCluster(
                    start_time=ts,
                    end_time=ts,
                )

            # Add to current cluster
            current_cluster.entries.append(mf_entry)
            current_cluster.end_time = ts
            current_cluster.sources.add(mf_entry.source_file)

            level = mf_entry.entry.level.value if mf_entry.entry.level else "UNKNOWN"
            current_cluster.levels[level] = current_cluster.levels.get(level, 0) + 1

            if self._is_error(mf_entry.entry):
                current_cluster.error_count += 1

        # Handle last cluster
        if current_cluster and len(current_cluster.entries) > 1 and len(current_cluster.sources) > 1:
            current_cluster.cluster_id = len(clusters) + 1
            self._finalize_cluster(current_cluster)
            if len(clusters) < self.max_clusters:
                clusters.append(current_cluster)

        result.correlation_clusters = clusters
        result.entries_per_file = dict(entry_counts)
        result.total_entries = sum(entry_counts.values())

        return result

    def _finalize_cluster(self, cluster: CorrelationCluster) -> None:
        """Generate summary for a correlation cluster."""
        parts = []
        parts.append(f"{len(cluster.entries)} events across {len(cluster.sources)} sources")

        if cluster.error_count > 0:
            parts.append(f"{cluster.error_count} errors")

        duration = cluster.duration_ms
        if duration > 1000:
            parts.append(f"span: {duration/1000:.1f}s")
        elif duration > 0:
            parts.append(f"span: {duration:.0f}ms")

        cluster.summary = ", ".join(parts)

    def compare_files(
        self,
        file_paths: list[str],
        max_lines_per_file: int = 10000,
    ) -> MultiFileResult:
        """
        Compare error patterns between files.

        Args:
            file_paths: List of log file paths
            max_lines_per_file: Maximum lines to read from each file

        Returns:
            MultiFileResult with comparison data
        """
        result = MultiFileResult(
            operation="compare",
            files=file_paths,
        )

        # Collect errors from each file
        file_errors: dict[str, set[str]] = {}
        file_summaries: dict[str, dict[str, Any]] = {}

        for file_path in file_paths:
            parser = self._get_parser(file_path)
            errors: set[str] = set()
            level_counts: dict[str, int] = defaultdict(int)
            entry_count = 0
            error_count = 0
            warn_count = 0
            time_start: datetime | None = None
            time_end: datetime | None = None

            for entry in parser.parse_file(file_path, max_lines=max_lines_per_file):
                entry_count += 1

                if entry.timestamp:
                    if time_start is None or entry.timestamp < time_start:
                        time_start = entry.timestamp
                    if time_end is None or entry.timestamp > time_end:
                        time_end = entry.timestamp

                if entry.level:
                    level = entry.level.value if hasattr(entry.level, "value") else str(entry.level)
                    level_counts[level] = level_counts.get(level, 0) + 1

                    if level.upper() in self.ERROR_LEVELS:
                        error_count += 1
                        normalized = self._normalize_error(entry.message)
                        errors.add(normalized)
                    elif level.upper() in self.WARN_LEVELS:
                        warn_count += 1

            file_errors[file_path] = errors
            file_summaries[file_path] = {
                "entry_count": entry_count,
                "error_count": error_count,
                "warning_count": warn_count,
                "unique_error_patterns": len(errors),
                "level_distribution": dict(level_counts),
                "time_range": {
                    "start": time_start.isoformat() if time_start else None,
                    "end": time_end.isoformat() if time_end else None,
                },
            }
            result.entries_per_file[file_path] = entry_count

            # Update global time range
            if time_start and (result.time_range_start is None or time_start < result.time_range_start):
                result.time_range_start = time_start
            if time_end and (result.time_range_end is None or time_end > result.time_range_end):
                result.time_range_end = time_end

        # Find common and unique errors
        if len(file_paths) >= 2:
            all_errors = set()
            for errors in file_errors.values():
                all_errors.update(errors)

            common = all_errors.copy()
            for errors in file_errors.values():
                common &= errors

            result.common_errors = list(common)[:20]

            for file_path, errors in file_errors.items():
                unique = errors - common
                result.unique_errors[file_path] = list(unique)[:20]

        result.file_summaries = file_summaries
        result.total_entries = sum(result.entries_per_file.values())

        return result


def merge_log_files(
    file_paths: list[str],
    max_entries: int = 1000,
    max_lines_per_file: int = 10000,
) -> MultiFileResult:
    """
    Convenience function to merge log files by timestamp.

    Args:
        file_paths: List of log file paths
        max_entries: Maximum entries in result
        max_lines_per_file: Maximum lines to read per file

    Returns:
        MultiFileResult with merged entries
    """
    analyzer = MultiFileAnalyzer(max_entries=max_entries)
    return analyzer.merge_files(file_paths, max_lines_per_file)


def correlate_log_files(
    file_paths: list[str],
    time_window: int = 60,
    max_clusters: int = 50,
    max_lines_per_file: int = 10000,
) -> MultiFileResult:
    """
    Convenience function to correlate events across log files.

    Args:
        file_paths: List of log file paths
        time_window: Time window in seconds
        max_clusters: Maximum correlation clusters
        max_lines_per_file: Maximum lines to read per file

    Returns:
        MultiFileResult with correlation clusters
    """
    analyzer = MultiFileAnalyzer(time_window=time_window, max_clusters=max_clusters)
    return analyzer.correlate_files(file_paths, max_lines_per_file)


def compare_log_files(
    file_paths: list[str],
    max_lines_per_file: int = 10000,
) -> MultiFileResult:
    """
    Convenience function to compare error patterns across log files.

    Args:
        file_paths: List of log file paths
        max_lines_per_file: Maximum lines to read per file

    Returns:
        MultiFileResult with comparison data
    """
    analyzer = MultiFileAnalyzer()
    return analyzer.compare_files(file_paths, max_lines_per_file)
