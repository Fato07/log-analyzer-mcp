"""Summarizer analyzer - Generate debugging summary of log files."""

import os
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import Anomaly, FileInfo, LogFormat, TimeRange
from ..parsers.base import BaseLogParser, ParsedLogEntry
from .error_extractor import ErrorExtractor, ErrorGroup

# Output limits
MAX_TOP_ERRORS = 10
MAX_ANOMALIES = 20


@dataclass
class PerformanceMetrics:
    """Performance-related metrics from logs."""

    slow_requests_1s: int = 0  # Requests >1s
    slow_requests_5s: int = 0  # Requests >5s
    slow_requests_10s: int = 0  # Requests >10s
    avg_response_time_ms: float | None = None
    max_response_time_ms: float | None = None
    total_requests: int = 0
    throughput_per_minute: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "slow_requests_1s": self.slow_requests_1s,
            "slow_requests_5s": self.slow_requests_5s,
            "slow_requests_10s": self.slow_requests_10s,
            "avg_response_time_ms": self.avg_response_time_ms,
            "max_response_time_ms": self.max_response_time_ms,
            "total_requests": self.total_requests,
            "throughput_per_minute": self.throughput_per_minute,
        }


@dataclass
class SecurityIndicators:
    """Security-related indicators from logs."""

    failed_auth_attempts: int = 0
    suspicious_ips: list[str] = field(default_factory=list)
    error_4xx_count: int = 0
    error_5xx_count: int = 0
    paths_with_most_errors: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "failed_auth_attempts": self.failed_auth_attempts,
            "suspicious_ips": self.suspicious_ips[:10],  # Limit to top 10
            "error_4xx_count": self.error_4xx_count,
            "error_5xx_count": self.error_5xx_count,
            "paths_with_most_errors": dict(
                sorted(self.paths_with_most_errors.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
        }


@dataclass
class LogSummary:
    """Complete log summary."""

    file_info: FileInfo
    time_range: TimeRange
    level_distribution: dict[str, int] = field(default_factory=dict)
    top_errors: list[ErrorGroup] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    performance: PerformanceMetrics | None = None
    security: SecurityIndicators | None = None
    total_entries: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "file_info": {
                "path": self.file_info.path,
                "size_bytes": self.file_info.size_bytes,
                "total_lines": self.file_info.total_lines,
                "detected_format": self.file_info.detected_format.value,
                "encoding": self.file_info.encoding,
            },
            "time_range": {
                "start": self.time_range.start.isoformat() if self.time_range.start else None,
                "end": self.time_range.end.isoformat() if self.time_range.end else None,
                "duration_seconds": self.time_range.duration_seconds,
            },
            "level_distribution": self.level_distribution,
            "top_errors": [
                {
                    "template": e.template,
                    "count": e.count,
                    "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                    "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                }
                for e in self.top_errors
            ],
            "anomalies": [
                {
                    "type": a.type,
                    "description": a.description,
                    "severity": a.severity,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                }
                for a in self.anomalies
            ],
            "recommendations": self.recommendations,
            "performance": self.performance.to_dict() if self.performance else None,
            "security": self.security.to_dict() if self.security else None,
            "total_entries": self.total_entries,
        }


class Summarizer:
    """
    Log summarizer that generates debugging insights.
    Memory-efficient: processes entries in streaming fashion.
    """

    # Auth failure patterns
    AUTH_FAILURE_PATTERNS = [
        "authentication failed",
        "login failed",
        "invalid password",
        "access denied",
        "unauthorized",
        "permission denied",
        "401",
        "403",
    ]

    def __init__(
        self,
        file_path: str | Path,
        include_performance: bool = True,
        include_security: bool = True,
        detected_format: LogFormat = LogFormat.AUTO,
    ):
        """
        Initialize summarizer.

        Args:
            file_path: Path to the log file
            include_performance: Include performance metrics
            include_security: Include security indicators
            detected_format: Detected log format
        """
        # Ensure file_path is always a string
        self.file_path = str(file_path) if isinstance(file_path, Path) else file_path
        self.include_performance = include_performance
        self.include_security = include_security
        self.detected_format = detected_format

        # State
        self._total_entries = 0
        self._level_counts: Counter[str] = Counter()
        self._time_start: datetime | None = None
        self._time_end: datetime | None = None

        # Error tracking (delegate to ErrorExtractor)
        self._error_extractor = ErrorExtractor(
            include_warnings=True, max_errors=MAX_TOP_ERRORS, group_similar=True
        )

        # Performance tracking
        self._response_times: list[float] = []
        self._request_times: list[datetime] = []

        # Security tracking
        self._auth_failures = 0
        self._ip_counter: Counter[str] = Counter()
        self._status_codes: Counter[int] = Counter()
        self._path_errors: Counter[str] = Counter()

        # Anomaly detection
        self._entries_per_minute: Counter[str] = Counter()  # minute bucket -> count
        self._last_timestamp: datetime | None = None

    def _update_time_range(self, timestamp: datetime | None) -> None:
        """Update tracked time range."""
        if timestamp:
            if self._time_start is None or timestamp < self._time_start:
                self._time_start = timestamp
            if self._time_end is None or timestamp > self._time_end:
                self._time_end = timestamp

    def _check_auth_failure(self, message: str) -> bool:
        """Check if message indicates an auth failure."""
        message_lower = message.lower()
        return any(pattern in message_lower for pattern in self.AUTH_FAILURE_PATTERNS)

    def _get_minute_bucket(self, timestamp: datetime) -> str:
        """Get minute bucket key for timestamp."""
        return timestamp.strftime("%Y-%m-%d %H:%M")

    def process_entry(self, entry: ParsedLogEntry) -> None:
        """
        Process a single log entry.

        Args:
            entry: Parsed log entry
        """
        self._total_entries += 1
        self._update_time_range(entry.timestamp)

        # Track level distribution
        level = (entry.level or "UNKNOWN").upper()
        self._level_counts[level] += 1

        # Delegate error tracking
        self._error_extractor.process_entry(entry)

        # Track entries per minute for anomaly detection
        if entry.timestamp:
            bucket = self._get_minute_bucket(entry.timestamp)
            self._entries_per_minute[bucket] += 1
            self._last_timestamp = entry.timestamp

        # Extract metadata for performance/security
        metadata = entry.metadata

        # Performance metrics (for web access logs)
        if self.include_performance:
            # Check for response time in metadata
            response_time = metadata.get("response_time") or metadata.get("duration")
            if response_time is not None:
                try:
                    rt_ms = float(response_time)
                    self._response_times.append(rt_ms)
                    if entry.timestamp:
                        self._request_times.append(entry.timestamp)
                except (ValueError, TypeError):
                    pass

        # Security metrics
        if self.include_security:
            # Check for auth failures
            if self._check_auth_failure(entry.message):
                self._auth_failures += 1

            # Track IP addresses
            client_ip = metadata.get("client_ip") or metadata.get("ip")
            if client_ip:
                self._ip_counter[str(client_ip)] += 1

            # Track status codes (for web logs)
            status = metadata.get("status_code") or metadata.get("status")
            if status is not None:
                try:
                    status_int = int(status)
                    self._status_codes[status_int] += 1

                    # Track paths with errors
                    if status_int >= 400:
                        path = metadata.get("path") or metadata.get("url") or "unknown"
                        self._path_errors[str(path)] += 1
                except (ValueError, TypeError):
                    pass

    def _detect_anomalies(self) -> list[Anomaly]:
        """Detect anomalies in the log data."""
        anomalies: list[Anomaly] = []

        if not self._entries_per_minute:
            return anomalies

        # Calculate baseline metrics
        counts = list(self._entries_per_minute.values())
        if len(counts) < 3:
            return anomalies

        avg_count = sum(counts) / len(counts)
        max_count = max(counts)

        # Detect volume spikes (>3x average)
        spike_threshold = avg_count * 3
        for bucket, count in self._entries_per_minute.items():
            if count > spike_threshold and count == max_count:
                anomalies.append(
                    Anomaly(
                        type="spike",
                        description=f"Log volume spike: {count} entries in minute {bucket} (avg: {avg_count:.0f})",
                        severity="high" if count > avg_count * 5 else "medium",
                        timestamp=datetime.strptime(bucket, "%Y-%m-%d %H:%M") if bucket else None,
                        details={"count": count, "average": avg_count},
                    )
                )
                if len(anomalies) >= MAX_ANOMALIES:
                    break

        # Detect gaps in logging (>5 minutes without logs)
        if len(self._entries_per_minute) > 1:
            sorted_buckets = sorted(self._entries_per_minute.keys())
            for i in range(1, len(sorted_buckets)):
                try:
                    prev_time = datetime.strptime(sorted_buckets[i - 1], "%Y-%m-%d %H:%M")
                    curr_time = datetime.strptime(sorted_buckets[i], "%Y-%m-%d %H:%M")
                    gap = (curr_time - prev_time).total_seconds() / 60

                    if gap > 5:
                        anomalies.append(
                            Anomaly(
                                type="gap",
                                description=f"Logging gap of {gap:.0f} minutes between {sorted_buckets[i - 1]} and {sorted_buckets[i]}",
                                severity="medium" if gap < 15 else "high",
                                timestamp=prev_time,
                                details={"gap_minutes": gap},
                            )
                        )
                        if len(anomalies) >= MAX_ANOMALIES:
                            break
                except ValueError:
                    continue

        # Detect unusual level distribution
        total_entries = sum(self._level_counts.values())
        if total_entries > 100:
            error_levels = {"ERROR", "FATAL", "CRITICAL", "EMERGENCY"}
            error_count = sum(self._level_counts[lvl] for lvl in error_levels)
            error_rate = error_count / total_entries

            if error_rate > 0.1:  # >10% errors
                anomalies.append(
                    Anomaly(
                        type="unusual_level",
                        description=f"High error rate: {error_rate * 100:.1f}% of entries are errors",
                        severity="high" if error_rate > 0.25 else "medium",
                        timestamp=self._time_end,
                        details={"error_rate": error_rate, "error_count": error_count},
                    )
                )

        return anomalies[:MAX_ANOMALIES]

    def _generate_recommendations(self, anomalies: list[Anomaly], error_result: Any) -> list[str]:
        """Generate investigation recommendations."""
        recommendations: list[str] = []

        # Based on error count
        if error_result.total_errors > 0:
            recommendations.append(
                f"Investigate {error_result.total_errors} errors - "
                f"{error_result.unique_errors} unique error patterns detected"
            )

        # Based on anomalies
        for anomaly in anomalies[:3]:
            if anomaly.type == "spike":
                recommendations.append(
                    f"Review log spike at {anomaly.timestamp} for potential incident"
                )
            elif anomaly.type == "gap":
                recommendations.append("Check system health during logging gap - possible outage")
            elif anomaly.type == "unusual_level":
                recommendations.append("High error rate detected - prioritize error investigation")

        # Based on security indicators
        if self._auth_failures > 10:
            recommendations.append(
                f"High number of authentication failures ({self._auth_failures}) - "
                "check for brute force attempts"
            )

        # Based on performance
        if self._response_times:
            slow_count = sum(1 for rt in self._response_times if rt > 5000)
            if slow_count > len(self._response_times) * 0.1:
                recommendations.append(
                    f"{slow_count} slow requests (>5s) detected - investigate performance issues"
                )

        return recommendations[:5]  # Limit to 5 recommendations

    def _build_performance_metrics(self) -> PerformanceMetrics | None:
        """Build performance metrics from collected data."""
        if not self._response_times:
            return None

        metrics = PerformanceMetrics()
        metrics.total_requests = len(self._response_times)

        # Calculate slow request counts
        for rt in self._response_times:
            if rt > 10000:
                metrics.slow_requests_10s += 1
            if rt > 5000:
                metrics.slow_requests_5s += 1
            if rt > 1000:
                metrics.slow_requests_1s += 1

        # Calculate averages
        metrics.avg_response_time_ms = sum(self._response_times) / len(self._response_times)
        metrics.max_response_time_ms = max(self._response_times)

        # Calculate throughput
        if self._time_start and self._time_end:
            duration_minutes = (self._time_end - self._time_start).total_seconds() / 60
            if duration_minutes > 0:
                metrics.throughput_per_minute = metrics.total_requests / duration_minutes

        return metrics

    def _build_security_indicators(self) -> SecurityIndicators | None:
        """Build security indicators from collected data."""
        indicators = SecurityIndicators()
        indicators.failed_auth_attempts = self._auth_failures

        # Find suspicious IPs (high request count)
        if self._ip_counter:
            avg_requests = sum(self._ip_counter.values()) / len(self._ip_counter)
            threshold = avg_requests * 10
            suspicious = [ip for ip, count in self._ip_counter.most_common(20) if count > threshold]
            indicators.suspicious_ips = suspicious

        # Count 4xx and 5xx errors
        for status, count in self._status_codes.items():
            if 400 <= status < 500:
                indicators.error_4xx_count += count
            elif status >= 500:
                indicators.error_5xx_count += count

        # Paths with most errors
        indicators.paths_with_most_errors = dict(self._path_errors.most_common(10))

        return indicators

    def finalize(self) -> LogSummary:
        """
        Finalize summary and return results.

        Returns:
            LogSummary with all analysis results
        """
        # Finalize error extraction
        error_result = self._error_extractor.finalize()

        # Detect anomalies
        anomalies = self._detect_anomalies()

        # Generate recommendations
        recommendations = self._generate_recommendations(anomalies, error_result)

        # Build file info
        try:
            file_size = os.path.getsize(self.file_path)
        except OSError:
            file_size = 0

        file_info = FileInfo(
            path=self.file_path,
            size_bytes=file_size,
            total_lines=self._total_entries,
            detected_format=self.detected_format,
            encoding="utf-8",
        )

        # Build time range
        time_range = TimeRange(start=self._time_start, end=self._time_end)

        return LogSummary(
            file_info=file_info,
            time_range=time_range,
            level_distribution=dict(self._level_counts),
            top_errors=error_result.error_groups[:MAX_TOP_ERRORS],
            anomalies=anomalies,
            recommendations=recommendations,
            performance=self._build_performance_metrics() if self.include_performance else None,
            security=self._build_security_indicators() if self.include_security else None,
            total_entries=self._total_entries,
        )

    def summarize_file(self, parser: BaseLogParser, max_lines: int = 10000) -> LogSummary:
        """
        Generate summary for a log file.

        Args:
            parser: Parser to use for parsing log entries
            max_lines: Maximum lines to process

        Returns:
            LogSummary with all analysis results
        """
        for entry in parser.parse_file(self.file_path, max_lines=max_lines):
            self.process_entry(entry)
        return self.finalize()

    def summarize_entries(self, entries: Iterator[ParsedLogEntry]) -> LogSummary:
        """
        Generate summary from an iterator of entries.

        Args:
            entries: Iterator of parsed log entries

        Returns:
            LogSummary with all analysis results
        """
        for entry in entries:
            self.process_entry(entry)
        return self.finalize()


def summarize_log(
    parser: BaseLogParser,
    file_path: str,
    include_performance: bool = True,
    include_security: bool = True,
    detected_format: LogFormat = LogFormat.AUTO,
    max_lines: int = 10000,
) -> LogSummary:
    """
    Convenience function to summarize a log file.

    Args:
        parser: Parser to use for parsing log entries
        file_path: Path to the log file
        include_performance: Include performance metrics
        include_security: Include security indicators
        detected_format: Detected log format
        max_lines: Maximum lines to process

    Returns:
        LogSummary with all analysis results
    """
    summarizer = Summarizer(
        file_path=file_path,
        include_performance=include_performance,
        include_security=include_security,
        detected_format=detected_format,
    )
    return summarizer.summarize_file(parser, max_lines=max_lines)
