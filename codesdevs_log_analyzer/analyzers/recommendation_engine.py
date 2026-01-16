"""Recommendation engine - Generate actionable recommendations from log analysis."""

import re
from dataclasses import dataclass, field
from typing import Any

from ..parsers.base import ParsedLogEntry

# Common error patterns with associated recommendations
ERROR_PATTERNS: list[tuple[str, str, list[str]]] = [
    # Database issues
    (
        r"(?:connection|pool)\s*(?:refused|exhausted|timeout|failed|error)",
        "database_connection",
        [
            "Check database server is running and accessible",
            "Verify database connection string and credentials",
            "Increase connection pool size if under heavy load",
            "Check network connectivity to database host",
        ],
    ),
    (
        r"(?:deadlock|lock\s*wait\s*timeout)",
        "database_deadlock",
        [
            "Review transaction isolation levels",
            "Check for long-running transactions",
            "Optimize query patterns to reduce lock contention",
            "Consider using optimistic locking",
        ],
    ),
    (
        r"(?:query\s*timeout|slow\s*query|execution\s*timeout)",
        "query_timeout",
        [
            "Optimize slow queries with proper indexes",
            "Check query execution plans",
            "Consider query caching or pagination",
            "Review database query patterns",
        ],
    ),
    # Memory issues
    (
        r"(?:out\s*of\s*memory|oom|memory\s*exhausted|heap\s*space)",
        "memory_exhaustion",
        [
            "Increase application memory limits",
            "Check for memory leaks",
            "Optimize data structures and caching",
            "Consider horizontal scaling",
        ],
    ),
    (
        r"(?:gc\s*overhead|garbage\s*collection\s*limit)",
        "gc_pressure",
        [
            "Tune garbage collector settings",
            "Reduce object allocation rate",
            "Increase heap size",
            "Profile memory usage patterns",
        ],
    ),
    # Network issues
    (
        r"(?:connection\s*reset|socket\s*timeout|network\s*unreachable)",
        "network_error",
        [
            "Check network connectivity and firewall rules",
            "Verify DNS resolution",
            "Review connection timeout settings",
            "Check for network partitions",
        ],
    ),
    (
        r"(?:ssl|tls).*(?:handshake|certificate|verify)",
        "ssl_error",
        [
            "Verify SSL certificate validity",
            "Check certificate chain completeness",
            "Ensure compatible TLS versions",
            "Review SSL configuration",
        ],
    ),
    # Authentication/Authorization
    (
        r"(?:authentication\s*fail|invalid\s*credentials|access\s*denied|unauthorized)",
        "auth_failure",
        [
            "Verify credentials and tokens",
            "Check authentication service availability",
            "Review permission and role configurations",
            "Check for expired tokens or sessions",
        ],
    ),
    # Resource exhaustion
    (
        r"(?:too\s*many\s*open\s*files|file\s*descriptor|ulimit)",
        "file_descriptor_exhaustion",
        [
            "Increase file descriptor limits (ulimit -n)",
            "Check for resource leaks",
            "Review connection pooling configuration",
            "Close unused file handles",
        ],
    ),
    (
        r"(?:disk\s*full|no\s*space\s*left|quota\s*exceeded)",
        "disk_space",
        [
            "Free up disk space",
            "Implement log rotation",
            "Clean up temporary files",
            "Increase storage capacity",
        ],
    ),
    # HTTP errors
    (
        r"(?:5[0-9]{2}|internal\s*server\s*error|bad\s*gateway|service\s*unavailable)",
        "http_5xx",
        [
            "Check upstream service health",
            "Review application logs for errors",
            "Verify service dependencies",
            "Check resource utilization",
        ],
    ),
    (
        r"(?:4[0-9]{2}|not\s*found|bad\s*request|forbidden)",
        "http_4xx",
        [
            "Verify request URL and parameters",
            "Check authentication headers",
            "Review API documentation",
            "Validate request body format",
        ],
    ),
    # Rate limiting
    (
        r"(?:rate\s*limit|throttl|too\s*many\s*requests|429)",
        "rate_limiting",
        [
            "Implement request rate limiting",
            "Add request queuing or backoff",
            "Review API usage patterns",
            "Consider caching frequent requests",
        ],
    ),
    # Timeouts
    (
        r"(?:request\s*timeout|read\s*timeout|write\s*timeout)",
        "timeout",
        [
            "Increase timeout values if appropriate",
            "Check for slow dependencies",
            "Optimize request handling",
            "Consider async processing",
        ],
    ),
    # Service issues
    (
        r"(?:service\s*unavailable|upstream\s*down|connection\s*refused)",
        "service_unavailable",
        [
            "Check dependent service health",
            "Implement circuit breaker pattern",
            "Review service discovery configuration",
            "Check load balancer settings",
        ],
    ),
    # Queue issues
    (
        r"(?:queue\s*full|message\s*rejected|broker\s*unavailable)",
        "queue_issues",
        [
            "Check message broker health",
            "Increase queue capacity",
            "Review consumer throughput",
            "Implement dead letter queues",
        ],
    ),
]

# Common causal indicators - patterns that often precede errors
CAUSAL_INDICATORS: list[tuple[str, str, float]] = [
    # Database precursors
    (r"connection\s*pool\s*(?:low|warning|exhausted)", "resource_exhaustion", 0.9),
    (r"(?:slow|long[- ]running)\s*query", "performance_degradation", 0.8),
    (r"(?:max\s*connections|connection\s*limit)", "capacity_limit", 0.85),
    # Memory precursors
    (r"(?:memory\s*(?:high|warning)|heap\s*usage\s*(?:high|>))", "memory_pressure", 0.85),
    (r"gc\s*pause\s*(?:long|warning)", "gc_pressure", 0.75),
    # Network precursors
    (r"(?:latency\s*(?:high|spike)|response\s*time\s*(?:high|degraded))", "latency_issue", 0.7),
    (r"(?:retry|retrying|reconnect)", "connectivity_issue", 0.65),
    (r"(?:dns\s*(?:timeout|failure)|name\s*resolution)", "dns_issue", 0.8),
    # Load precursors
    (r"(?:cpu\s*(?:high|>)|load\s*average\s*(?:high|>))", "cpu_pressure", 0.75),
    (r"(?:thread\s*pool\s*(?:exhausted|full)|worker\s*queue\s*full)", "thread_exhaustion", 0.85),
    (r"(?:request\s*queue\s*(?:growing|backlog)|pending\s*requests)", "request_backlog", 0.8),
    # Authentication precursors
    (r"(?:token\s*expir|session\s*expir|credential\s*refresh)", "auth_expiration", 0.7),
    # Service precursors
    (r"(?:health\s*check\s*fail|heartbeat\s*miss)", "service_health", 0.85),
    (r"(?:circuit\s*(?:open|breaker)|fallback\s*triggered)", "circuit_breaker", 0.9),
]


@dataclass
class CausalChainLink:
    """A single link in a causal chain."""

    entry: ParsedLogEntry
    category: str
    time_offset_seconds: float  # Time before the anchor event
    confidence: float  # How confident we are this is causally related
    description: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "line_number": self.entry.line_number,
            "timestamp": self.entry.timestamp.isoformat() if self.entry.timestamp else None,
            "level": self.entry.level.value if self.entry.level else None,
            "message": self.entry.message[:300],
            "category": self.category,
            "time_offset_seconds": round(self.time_offset_seconds, 2),
            "confidence": round(self.confidence, 2),
            "description": self.description,
        }


@dataclass
class CausalChain:
    """A chain of events leading to an error."""

    anchor: ParsedLogEntry
    error_category: str
    chain_links: list[CausalChainLink] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    root_cause_hypothesis: str | None = None
    confidence_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "anchor": {
                "line_number": self.anchor.line_number,
                "timestamp": self.anchor.timestamp.isoformat() if self.anchor.timestamp else None,
                "level": self.anchor.level.value if self.anchor.level else None,
                "message": self.anchor.message[:500],
            },
            "error_category": self.error_category,
            "chain_links": [link.to_dict() for link in self.chain_links],
            "root_cause_hypothesis": self.root_cause_hypothesis,
            "recommendations": self.recommendations,
            "confidence_score": round(self.confidence_score, 2),
        }


class RecommendationEngine:
    """
    Generate actionable recommendations based on log analysis.

    Features:
    - Pattern-based error categorization
    - Causal chain detection
    - Context-aware recommendations
    - Root cause hypothesis generation
    """

    def __init__(self) -> None:
        """Initialize recommendation engine with compiled patterns."""
        # Compile error patterns
        self._error_patterns: list[tuple[re.Pattern[str], str, list[str]]] = [
            (re.compile(pattern, re.IGNORECASE), category, recs)
            for pattern, category, recs in ERROR_PATTERNS
        ]

        # Compile causal indicators
        self._causal_indicators: list[tuple[re.Pattern[str], str, float]] = [
            (re.compile(pattern, re.IGNORECASE), category, confidence)
            for pattern, category, confidence in CAUSAL_INDICATORS
        ]

    def categorize_error(self, entry: ParsedLogEntry) -> tuple[str, list[str]]:
        """
        Categorize an error and get associated recommendations.

        Args:
            entry: Log entry to categorize

        Returns:
            Tuple of (category, recommendations)
        """
        text = f"{entry.message} {entry.raw_line}"

        for pattern, category, recommendations in self._error_patterns:
            if pattern.search(text):
                return category, recommendations

        return "unknown", ["Review error message and stack trace for details"]

    def detect_causal_indicator(
        self, entry: ParsedLogEntry
    ) -> tuple[str | None, float]:
        """
        Check if an entry is a potential causal indicator.

        Args:
            entry: Log entry to check

        Returns:
            Tuple of (category, confidence) or (None, 0) if not a causal indicator
        """
        text = f"{entry.message} {entry.raw_line}"

        for pattern, category, confidence in self._causal_indicators:
            if pattern.search(text):
                return category, confidence

        return None, 0.0

    def build_causal_chain(
        self,
        anchor: ParsedLogEntry,
        events_before: list[ParsedLogEntry],
    ) -> CausalChain:
        """
        Build a causal chain for an error event.

        Args:
            anchor: The error/anchor event
            events_before: Events that occurred before the anchor

        Returns:
            CausalChain with detected causal relationships
        """
        # Categorize the anchor error
        error_category, recommendations = self.categorize_error(anchor)

        chain = CausalChain(
            anchor=anchor,
            error_category=error_category,
            recommendations=recommendations.copy(),
        )

        if not anchor.timestamp:
            return chain

        # Analyze events before the anchor for causal indicators
        causal_links: list[CausalChainLink] = []
        seen_categories: set[str] = set()

        for event in events_before:
            if not event.timestamp:
                continue

            category, confidence = self.detect_causal_indicator(event)
            if category and category not in seen_categories:
                time_diff = (anchor.timestamp - event.timestamp).total_seconds()

                # Higher confidence for events closer to the anchor
                time_factor = max(0.5, 1.0 - (time_diff / 300))  # Decay over 5 minutes
                adjusted_confidence = confidence * time_factor

                description = self._generate_link_description(category, time_diff)

                link = CausalChainLink(
                    entry=event,
                    category=category,
                    time_offset_seconds=time_diff,
                    confidence=adjusted_confidence,
                    description=description,
                )
                causal_links.append(link)
                seen_categories.add(category)

        # Sort by time offset (earliest first)
        causal_links.sort(key=lambda x: -x.time_offset_seconds)

        chain.chain_links = causal_links

        # Generate root cause hypothesis
        if causal_links:
            chain.root_cause_hypothesis = self._generate_hypothesis(
                error_category, causal_links
            )
            chain.confidence_score = self._calculate_chain_confidence(causal_links)

            # Add recommendations based on causal chain
            additional_recs = self._get_chain_recommendations(causal_links)
            for rec in additional_recs:
                if rec not in chain.recommendations:
                    chain.recommendations.append(rec)
        else:
            chain.confidence_score = 0.3  # Lower confidence without causal chain

        return chain

    def _generate_link_description(self, category: str, time_offset: float) -> str:
        """Generate a human-readable description for a causal link."""
        time_str = self._format_time_offset(time_offset)

        descriptions: dict[str, str] = {
            "resource_exhaustion": f"Resource exhaustion detected {time_str} before error",
            "performance_degradation": f"Performance degradation observed {time_str} before error",
            "capacity_limit": f"Capacity limit reached {time_str} before error",
            "memory_pressure": f"Memory pressure detected {time_str} before error",
            "gc_pressure": f"GC pressure observed {time_str} before error",
            "latency_issue": f"Latency spike detected {time_str} before error",
            "connectivity_issue": f"Connectivity issues observed {time_str} before error",
            "dns_issue": f"DNS resolution problem {time_str} before error",
            "cpu_pressure": f"CPU pressure detected {time_str} before error",
            "thread_exhaustion": f"Thread pool exhaustion {time_str} before error",
            "request_backlog": f"Request backlog building {time_str} before error",
            "auth_expiration": f"Authentication/session issue {time_str} before error",
            "service_health": f"Service health degradation {time_str} before error",
            "circuit_breaker": f"Circuit breaker triggered {time_str} before error",
        }

        return descriptions.get(category, f"Related event {time_str} before error")

    def _format_time_offset(self, seconds: float) -> str:
        """Format time offset in human-readable form."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.1f}m"
        else:
            return f"{seconds / 3600:.1f}h"

    def _generate_hypothesis(
        self, error_category: str, causal_links: list[CausalChainLink]
    ) -> str:
        """Generate a root cause hypothesis based on error and causal chain."""
        if not causal_links:
            return f"Isolated {error_category} error without clear precursors"

        # Build chain description
        chain_categories = [link.category for link in causal_links]

        # Common causal patterns
        if "resource_exhaustion" in chain_categories:
            if "memory_pressure" in chain_categories:
                return "Memory pressure led to resource exhaustion, causing the error"
            if "thread_exhaustion" in chain_categories:
                return "Thread pool exhaustion caused resource starvation and subsequent failure"
            return "Resource exhaustion cascade leading to service degradation"

        if "performance_degradation" in chain_categories:
            if "latency_issue" in chain_categories:
                return "Performance degradation caused latency spikes, leading to timeouts"
            return "Gradual performance degradation culminated in service failure"

        if "connectivity_issue" in chain_categories:
            if "dns_issue" in chain_categories:
                return "DNS resolution issues caused connection failures"
            return "Network connectivity problems caused service disruption"

        if "circuit_breaker" in chain_categories:
            return "Upstream service failures triggered circuit breaker, causing cascading failure"

        if "service_health" in chain_categories:
            return "Dependent service health degradation led to this failure"

        # Default hypothesis
        primary_cause = causal_links[0].category.replace("_", " ")
        return f"Chain of events starting with {primary_cause} led to {error_category.replace('_', ' ')}"

    def _calculate_chain_confidence(self, causal_links: list[CausalChainLink]) -> float:
        """Calculate overall confidence score for the causal chain."""
        if not causal_links:
            return 0.3

        # Average confidence of all links, weighted by time proximity
        total_weighted = sum(link.confidence for link in causal_links)
        avg_confidence = total_weighted / len(causal_links)

        # Boost for multiple corroborating indicators
        corroboration_boost = min(0.2, len(causal_links) * 0.05)

        return min(0.95, avg_confidence + corroboration_boost)

    def _get_chain_recommendations(
        self, causal_links: list[CausalChainLink]
    ) -> list[str]:
        """Get additional recommendations based on causal chain."""
        recommendations: list[str] = []
        categories = {link.category for link in causal_links}

        if "resource_exhaustion" in categories:
            recommendations.append("Monitor resource utilization and implement alerts")
            recommendations.append("Consider autoscaling or resource limits")

        if "memory_pressure" in categories:
            recommendations.append("Profile memory usage and optimize allocations")

        if "performance_degradation" in categories:
            recommendations.append("Implement performance monitoring and SLOs")

        if "connectivity_issue" in categories:
            recommendations.append("Implement retry logic with exponential backoff")

        if "circuit_breaker" in categories:
            recommendations.append("Review circuit breaker thresholds and fallback strategies")

        if "service_health" in categories:
            recommendations.append("Implement health checks and graceful degradation")

        return recommendations


def get_recommendations_for_error(entry: ParsedLogEntry) -> tuple[str, list[str]]:
    """
    Get recommendations for a single error entry.

    Args:
        entry: Log entry to analyze

    Returns:
        Tuple of (error_category, recommendations)
    """
    engine = RecommendationEngine()
    return engine.categorize_error(entry)


def build_causal_chain(
    anchor: ParsedLogEntry,
    events_before: list[ParsedLogEntry],
) -> CausalChain:
    """
    Build a causal chain for an error event.

    Args:
        anchor: The error/anchor event
        events_before: Events that occurred before the anchor

    Returns:
        CausalChain with detected causal relationships
    """
    engine = RecommendationEngine()
    return engine.build_causal_chain(anchor, events_before)
