"""Pattern suggester analyzer - Suggest useful search patterns based on log content."""

from __future__ import annotations

import contextlib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ..parsers.base import BaseLogParser
from ..utils.file_handler import stream_file


@dataclass
class SuggestedPattern:
    """A suggested search pattern with metadata."""

    pattern: str  # The regex pattern
    description: str  # What it matches
    category: str  # error, identifier, endpoint, security, performance, custom
    match_count: int  # How many lines matched
    examples: list[str] = field(default_factory=list)  # Sample matches (max 3)
    priority: str = "medium"  # high, medium, low

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "pattern": self.pattern,
            "description": self.description,
            "category": self.category,
            "match_count": self.match_count,
            "examples": self.examples[:3],
            "priority": self.priority,
        }


@dataclass
class PatternSuggestionResult:
    """Result of pattern suggestion analysis."""

    patterns: list[SuggestedPattern] = field(default_factory=list)
    analysis_summary: str = ""
    lines_analyzed: int = 0
    unique_levels: set[str] = field(default_factory=set)
    error_count: int = 0
    warning_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "patterns": [p.to_dict() for p in self.patterns],
            "analysis_summary": self.analysis_summary,
            "lines_analyzed": self.lines_analyzed,
            "unique_levels": list(self.unique_levels),
            "error_count": self.error_count,
            "warning_count": self.warning_count,
        }


class PatternSuggester:
    """
    Analyze logs and suggest useful search patterns.

    This analyzer scans log content to identify:
    - Common error templates (normalized error messages)
    - Identifiers (UUIDs, request IDs, user IDs)
    - IP addresses (internal vs external)
    - HTTP endpoints with issues
    - Performance indicators (slow requests)
    - Security indicators (auth failures)
    """

    # Built-in pattern detectors
    IDENTIFIER_PATTERNS = {
        "uuid": (
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "UUID identifiers",
        ),
        "request_id": (
            r"(?:req|request|trace|correlation)[_-]?(?:id)?[=:\s]+([a-zA-Z0-9_-]{8,})",
            "Request/trace IDs",
        ),
        "user_id": (
            r"(?:user|uid|account)[_-]?(?:id)?[=:\s]+([a-zA-Z0-9_-]+)",
            "User/account IDs",
        ),
        "session_id": (
            r"(?:session|sess)[_-]?(?:id)?[=:\s]+([a-zA-Z0-9_-]{8,})",
            "Session IDs",
        ),
    }

    IP_PATTERNS = {
        "ipv4": (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "IPv4 addresses",
        ),
        "ipv6": (
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            "IPv6 addresses",
        ),
    }

    ERROR_PATTERNS = {
        "exception": (
            r"(?:Exception|Error|Failure|Failed):\s*(.+)",
            "Exception messages",
        ),
        "connection": (
            r"(?:connection|connect)\s+(?:refused|timeout|reset|failed|error)",
            "Connection issues",
        ),
        "timeout": (
            r"(?:timeout|timed?\s*out)\s*(?:after|waiting|exceeded)?",
            "Timeout errors",
        ),
        "null_pointer": (
            r"(?:null|nil|none)\s*(?:pointer|reference|object)?(?:\s+exception)?",
            "Null/nil errors",
        ),
        "permission": (
            r"(?:permission|access)\s+(?:denied|forbidden|rejected)",
            "Permission errors",
        ),
    }

    SECURITY_PATTERNS = {
        "auth_failure": (
            r"(?:auth|authentication|login)\s+(?:failed|failure|error|denied)",
            "Authentication failures",
        ),
        "invalid_token": (
            r"(?:invalid|expired|malformed)\s+(?:token|jwt|session|credential)",
            "Token/credential issues",
        ),
        "unauthorized": (
            r"\b(?:unauthorized|unauthenticated|forbidden)\b",
            "Unauthorized access",
        ),
        "suspicious": (
            r"(?:suspicious|malicious|attack|injection|sql\s*injection|xss)",
            "Security threats",
        ),
    }

    PERFORMANCE_PATTERNS = {
        "slow_request": (
            r"(?:took|duration|elapsed|latency)[=:\s]*(\d{4,})\s*(?:ms|milliseconds?)",
            "Slow requests (>1s)",
        ),
        "high_memory": (
            r"(?:memory|heap|ram)[=:\s]*(\d+)\s*(?:MB|GB|bytes)",
            "Memory usage",
        ),
        "queue_depth": (
            r"(?:queue|backlog|pending)[=:\s]*(\d+)",
            "Queue depth",
        ),
    }

    HTTP_PATTERNS = {
        "http_error": (
            r'\b(?:GET|POST|PUT|DELETE|PATCH)\s+(/[^\s"]*)\s+(?:HTTP/[\d.]+\s+)?([45]\d{2})',
            "HTTP 4xx/5xx errors",
        ),
        "api_endpoint": (
            r'(?:GET|POST|PUT|DELETE|PATCH)\s+(/api/[^\s"?]+)',
            "API endpoints",
        ),
    }

    # Error levels
    ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL", "EMERGENCY", "ERR", "SEVERE"}
    WARNING_LEVELS = {"WARN", "WARNING", "WRN"}

    def __init__(self) -> None:
        """Initialize the pattern suggester."""
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns."""
        all_patterns = {
            **self.IDENTIFIER_PATTERNS,
            **self.IP_PATTERNS,
            **self.ERROR_PATTERNS,
            **self.SECURITY_PATTERNS,
            **self.PERFORMANCE_PATTERNS,
            **self.HTTP_PATTERNS,
        }
        for name, (pattern, _) in all_patterns.items():
            with contextlib.suppress(re.error):
                self._compiled_patterns[name] = re.compile(pattern, re.IGNORECASE)

    def analyze_file(
        self,
        file_path: str,
        parser: BaseLogParser,
        focus: str = "all",
        max_patterns: int = 10,
        max_lines: int = 10000,
    ) -> PatternSuggestionResult:
        """
        Analyze a log file and suggest useful search patterns.

        Args:
            file_path: Path to the log file
            parser: Log parser to use
            focus: Analysis focus - "all", "errors", "security", "performance", "identifiers"
            max_patterns: Maximum number of patterns to suggest
            max_lines: Maximum lines to analyze

        Returns:
            PatternSuggestionResult with suggested patterns
        """
        result = PatternSuggestionResult()

        # Counters for pattern matches
        pattern_matches: dict[str, Counter[str]] = {
            "error_templates": Counter(),
            "identifiers": Counter(),
            "ips": Counter(),
            "endpoints": Counter(),
            "security": Counter(),
            "performance": Counter(),
        }

        # Sample matches for each pattern
        pattern_examples: dict[str, list[str]] = {
            "error_templates": [],
            "identifiers": [],
            "ips": [],
            "endpoints": [],
            "security": [],
            "performance": [],
        }

        # Process lines
        for line_num, raw_line in stream_file(file_path, max_lines=max_lines):
            result.lines_analyzed += 1
            entry = parser.parse_line(raw_line, line_num)

            if entry is None:
                continue

            # Track levels
            if entry.level:
                level = entry.level.value.upper()
                result.unique_levels.add(level)
                if level in self.ERROR_LEVELS:
                    result.error_count += 1
                elif level in self.WARNING_LEVELS:
                    result.warning_count += 1

            message = entry.message

            # Analyze based on focus
            if focus in ("all", "errors"):
                self._extract_error_patterns(message, pattern_matches, pattern_examples)

            if focus in ("all", "identifiers"):
                self._extract_identifier_patterns(message, pattern_matches, pattern_examples)

            if focus in ("all", "security"):
                self._extract_security_patterns(message, pattern_matches, pattern_examples)

            if focus in ("all", "performance"):
                self._extract_performance_patterns(message, pattern_matches, pattern_examples)

            # Extract endpoints from raw line (might have HTTP method)
            if focus in ("all", "errors"):
                self._extract_http_patterns(raw_line, pattern_matches, pattern_examples)

        # Build suggested patterns
        result.patterns = self._build_suggestions(
            pattern_matches, pattern_examples, max_patterns, result
        )

        # Generate summary
        result.analysis_summary = self._generate_summary(result)

        return result

    def _extract_error_patterns(
        self,
        message: str,
        matches: dict[str, Counter[str]],
        examples: dict[str, list[str]],
    ) -> None:
        """Extract error patterns from message."""
        for name, (_pattern, _) in self.ERROR_PATTERNS.items():
            if name in self._compiled_patterns:
                match = self._compiled_patterns[name].search(message)
                if match:
                    # Normalize the error message
                    normalized = self._normalize_error(message)
                    matches["error_templates"][normalized] += 1
                    if len(examples["error_templates"]) < 10:
                        examples["error_templates"].append(message[:200])

    def _extract_identifier_patterns(
        self,
        message: str,
        matches: dict[str, Counter[str]],
        examples: dict[str, list[str]],
    ) -> None:
        """Extract identifier patterns from message."""
        for name, (_pattern, _) in self.IDENTIFIER_PATTERNS.items():
            if name in self._compiled_patterns:
                found = self._compiled_patterns[name].findall(message)
                for match in found[:5]:  # Limit matches per line
                    # Use the pattern name as key
                    matches["identifiers"][name] += 1
                    if len(examples["identifiers"]) < 10:
                        example = match if isinstance(match, str) else match[0] if match else ""
                        if example and example not in examples["identifiers"]:
                            examples["identifiers"].append(example)

    def _extract_security_patterns(
        self,
        message: str,
        matches: dict[str, Counter[str]],
        examples: dict[str, list[str]],
    ) -> None:
        """Extract security-related patterns."""
        for name, (_pattern, _) in self.SECURITY_PATTERNS.items():
            if name in self._compiled_patterns and self._compiled_patterns[name].search(message):
                matches["security"][name] += 1
                if len(examples["security"]) < 10:
                    examples["security"].append(message[:200])

    def _extract_performance_patterns(
        self,
        message: str,
        matches: dict[str, Counter[str]],
        examples: dict[str, list[str]],
    ) -> None:
        """Extract performance-related patterns."""
        for name, (_pattern, _) in self.PERFORMANCE_PATTERNS.items():
            if name in self._compiled_patterns:
                match = self._compiled_patterns[name].search(message)
                if match:
                    matches["performance"][name] += 1
                    if len(examples["performance"]) < 10:
                        examples["performance"].append(message[:200])

    def _extract_http_patterns(
        self,
        line: str,
        matches: dict[str, Counter[str]],
        examples: dict[str, list[str]],
    ) -> None:
        """Extract HTTP-related patterns."""
        for name, (_pattern, _) in self.HTTP_PATTERNS.items():
            if name in self._compiled_patterns:
                match = self._compiled_patterns[name].search(line)
                if match:
                    if name == "http_error":
                        endpoint = match.group(1)
                        status = match.group(2)
                        matches["endpoints"][f"{endpoint} ({status})"] += 1
                    elif name == "api_endpoint":
                        endpoint = match.group(1)
                        matches["endpoints"][endpoint] += 1

                    if len(examples["endpoints"]) < 10:
                        examples["endpoints"].append(line[:200])

    def _normalize_error(self, message: str) -> str:
        """Normalize an error message by replacing variable parts."""
        normalized = message

        # Replace common variable patterns
        replacements = [
            (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>"),
            (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>"),
            (r"\b\d{10,}\b", "<ID>"),
            (r"\b\d+\b", "<N>"),
            (r"'[^']+?'", "'<VAL>'"),
            (r'"[^"]+?"', '"<VAL>"'),
            (r"/[a-zA-Z0-9/_-]+/[a-zA-Z0-9._-]+", "<PATH>"),
        ]

        for pattern, replacement in replacements:
            normalized = re.sub(pattern, replacement, normalized)

        # Truncate long messages
        if len(normalized) > 100:
            normalized = normalized[:100] + "..."

        return normalized

    def _build_suggestions(
        self,
        matches: dict[str, Counter[str]],
        examples: dict[str, list[str]],
        max_patterns: int,
        result: PatternSuggestionResult,
    ) -> list[SuggestedPattern]:
        """Build the list of suggested patterns from collected data."""
        suggestions: list[SuggestedPattern] = []

        # Error templates (high priority if errors found)
        for template, count in matches["error_templates"].most_common(3):
            if count >= 2:  # Only suggest if seen multiple times
                suggestions.append(
                    SuggestedPattern(
                        pattern=re.escape(template).replace(r"\<", "<").replace(r"\>", ">"),
                        description=f"Error pattern ({count} occurrences)",
                        category="error",
                        match_count=count,
                        examples=examples["error_templates"][:3],
                        priority="high" if count >= 5 else "medium",
                    )
                )

        # Security patterns (high priority)
        for name, count in matches["security"].most_common(3):
            if count >= 1:
                pattern, desc = self.SECURITY_PATTERNS.get(name, (name, name))
                suggestions.append(
                    SuggestedPattern(
                        pattern=pattern,
                        description=f"{desc} ({count} occurrences)",
                        category="security",
                        match_count=count,
                        examples=examples["security"][:3],
                        priority="high",
                    )
                )

        # HTTP error endpoints
        for endpoint, count in matches["endpoints"].most_common(3):
            if count >= 2:
                suggestions.append(
                    SuggestedPattern(
                        pattern=re.escape(endpoint.split(" ")[0]),
                        description=f"Endpoint with errors ({count} occurrences)",
                        category="endpoint",
                        match_count=count,
                        examples=examples["endpoints"][:3],
                        priority="high" if count >= 5 else "medium",
                    )
                )

        # Performance patterns
        for name, count in matches["performance"].most_common(2):
            if count >= 1:
                pattern, desc = self.PERFORMANCE_PATTERNS.get(name, (name, name))
                suggestions.append(
                    SuggestedPattern(
                        pattern=pattern,
                        description=f"{desc} ({count} occurrences)",
                        category="performance",
                        match_count=count,
                        examples=examples["performance"][:3],
                        priority="medium",
                    )
                )

        # Identifier patterns (useful for tracing)
        for name, count in matches["identifiers"].most_common(3):
            if count >= 5:  # Only suggest if seen frequently
                pattern, desc = self.IDENTIFIER_PATTERNS.get(name, (name, name))
                suggestions.append(
                    SuggestedPattern(
                        pattern=pattern,
                        description=f"{desc} - useful for tracing ({count} occurrences)",
                        category="identifier",
                        match_count=count,
                        examples=examples["identifiers"][:3],
                        priority="low",
                    )
                )

        # Sort by priority and count
        priority_order = {"high": 0, "medium": 1, "low": 2}
        suggestions.sort(key=lambda x: (priority_order.get(x.priority, 1), -x.match_count))

        return suggestions[:max_patterns]

    def _generate_summary(self, result: PatternSuggestionResult) -> str:
        """Generate a summary of the analysis."""
        parts = [f"Analyzed {result.lines_analyzed:,} lines"]

        if result.error_count > 0:
            parts.append(f"{result.error_count:,} errors")
        if result.warning_count > 0:
            parts.append(f"{result.warning_count:,} warnings")

        parts.append(f"{len(result.patterns)} patterns suggested")

        # Add priority breakdown
        high = sum(1 for p in result.patterns if p.priority == "high")
        if high > 0:
            parts.append(f"{high} high priority")

        return ". ".join(parts) + "."
