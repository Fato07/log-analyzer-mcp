"""Sensitive data detector for log analysis.

Detects PII, credentials, and other sensitive information in log files.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from ..parsers.base import BaseLogParser
from ..utils.file_handler import stream_file


@dataclass
class SensitiveMatch:
    """A sensitive data match found in a log file."""

    line_number: int
    category: str  # email, credit_card, api_key, password, ssn, ip, etc.
    pattern_name: str  # Specific pattern that matched
    matched_text: str  # The actual matched text
    redacted_text: str  # Redacted version
    context: str  # Surrounding line context
    severity: str  # high, medium, low

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "line_number": self.line_number,
            "category": self.category,
            "pattern_name": self.pattern_name,
            "matched_text": self.matched_text,
            "redacted_text": self.redacted_text,
            "context": self.context[:200],
            "severity": self.severity,
        }


@dataclass
class SensitiveDataResult:
    """Result of sensitive data detection."""

    total_matches: int = 0
    matches_by_category: dict[str, int] = field(default_factory=dict)
    matches_by_severity: dict[str, int] = field(default_factory=dict)
    matches: list[SensitiveMatch] = field(default_factory=list)
    lines_scanned: int = 0
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_matches": self.total_matches,
            "matches_by_category": self.matches_by_category,
            "matches_by_severity": self.matches_by_severity,
            "matches": [m.to_dict() for m in self.matches],
            "lines_scanned": self.lines_scanned,
            "summary": self.summary,
        }


class SensitiveDataDetector:
    """
    Detect sensitive data in log files.

    Detects:
    - Email addresses
    - Credit card numbers (Visa, MasterCard, Amex, Discover)
    - API keys and tokens (common patterns)
    - Passwords in URLs or config
    - Social Security Numbers (SSN)
    - IP addresses (internal and external)
    - AWS keys
    - Private keys
    - JWT tokens
    - Database connection strings
    """

    # Sensitive data patterns with categories, severity, and redaction
    PATTERNS: dict[str, tuple[str, str, str, str]] = {
        # (pattern, category, severity, redaction_template)
        # Email addresses
        "email": (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "email",
            "medium",
            "[EMAIL_REDACTED]",
        ),
        # Credit card numbers (Visa, MasterCard, Amex, Discover)
        "credit_card_visa": (
            r"\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b",
            "credit_card",
            "high",
            "[CARD_REDACTED]",
        ),
        "credit_card_mastercard": (
            r"\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b",
            "credit_card",
            "high",
            "[CARD_REDACTED]",
        ),
        "credit_card_amex": (
            r"\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b",
            "credit_card",
            "high",
            "[CARD_REDACTED]",
        ),
        # Social Security Numbers
        "ssn": (
            r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
            "ssn",
            "high",
            "[SSN_REDACTED]",
        ),
        # AWS Access Keys
        "aws_access_key": (
            r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            "api_key",
            "high",
            "[AWS_KEY_REDACTED]",
        ),
        # AWS Secret Keys (40 char base64)
        "aws_secret_key": (
            r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",
            "api_key",
            "high",
            "[AWS_SECRET_REDACTED]",
        ),
        # Generic API keys (common formats)
        "api_key_generic": (
            r"(?i)(?:api[_-]?key|apikey|api_secret|secret_key)[=:\s]+['\"]?[A-Za-z0-9_-]{20,}['\"]?",
            "api_key",
            "high",
            "[API_KEY_REDACTED]",
        ),
        # Bearer tokens
        "bearer_token": (
            r"(?i)bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "token",
            "high",
            "[BEARER_TOKEN_REDACTED]",
        ),
        # JWT tokens
        "jwt_token": (
            r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            "token",
            "high",
            "[JWT_REDACTED]",
        ),
        # Password in URL
        "password_in_url": (
            r"(?i)(?:password|passwd|pwd)[=:][^&\s]+",
            "password",
            "high",
            "[PASSWORD_REDACTED]",
        ),
        # Basic auth in URL
        "basic_auth_url": (
            r"(?i)://[^:]+:[^@]+@",
            "password",
            "high",
            "://[CREDENTIALS_REDACTED]@",
        ),
        # Private key markers
        "private_key": (
            r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "private_key",
            "high",
            "[PRIVATE_KEY_REDACTED]",
        ),
        # Database connection strings
        "db_connection_string": (
            r"(?i)(?:mongodb|postgres|mysql|redis|amqp)://[^\s]+",
            "connection_string",
            "high",
            "[CONNECTION_STRING_REDACTED]",
        ),
        # GitHub tokens
        "github_token": (
            r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
            "token",
            "high",
            "[GITHUB_TOKEN_REDACTED]",
        ),
        # Slack tokens
        "slack_token": (
            r"\bxox[baprs]-[0-9A-Za-z-]+\b",
            "token",
            "high",
            "[SLACK_TOKEN_REDACTED]",
        ),
        # IPv4 addresses (marked as medium - often needed for debugging)
        "ipv4_address": (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "ip_address",
            "low",
            "[IP_REDACTED]",
        ),
        # Phone numbers (various formats)
        "phone_number": (
            r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "phone",
            "medium",
            "[PHONE_REDACTED]",
        ),
    }

    # Patterns to exclude (false positives)
    EXCLUDE_PATTERNS: list[str] = [
        r"0\.0\.0\.0",  # Not a real IP
        r"127\.0\.0\.1",  # Localhost
        r"localhost",
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Private IPs (optional)
        r"192\.168\.\d{1,3}\.\d{1,3}",  # Private IPs (optional)
        r"172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",  # Private IPs
    ]

    def __init__(self, include_private_ips: bool = False) -> None:
        """Initialize the detector.

        Args:
            include_private_ips: Whether to flag private IP addresses
        """
        self.include_private_ips = include_private_ips
        self._compiled_patterns: dict[str, re.Pattern[str]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns."""
        for name, (pattern, _, _, _) in self.PATTERNS.items():
            self._compiled_patterns[name] = re.compile(pattern)

    def analyze_file(
        self,
        file_path: str,
        parser: BaseLogParser,
        redact: bool = False,
        max_matches: int = 100,
        max_lines: int = 100000,
        categories: list[str] | None = None,
    ) -> SensitiveDataResult:
        """
        Scan a log file for sensitive data.

        Args:
            file_path: Path to the log file
            parser: Log parser to use
            redact: Whether to redact matched text in output
            max_matches: Maximum matches to return
            max_lines: Maximum lines to scan
            categories: Filter to specific categories (email, credit_card, etc.)

        Returns:
            SensitiveDataResult with matches and statistics
        """
        result = SensitiveDataResult()
        category_counts: Counter[str] = Counter()
        severity_counts: Counter[str] = Counter()

        for line_num, raw_line in stream_file(file_path, max_lines=max_lines):
            result.lines_scanned = line_num

            # Check each pattern
            for pattern_name, (_, category, severity, redaction) in self.PATTERNS.items():
                # Skip if filtering by category
                if categories and category not in categories:
                    continue

                compiled = self._compiled_patterns.get(pattern_name)
                if not compiled:
                    continue

                for match in compiled.finditer(raw_line):
                    matched_text = match.group(0)

                    # Skip excluded patterns
                    if self._should_exclude(matched_text, category):
                        continue

                    result.total_matches += 1
                    category_counts[category] += 1
                    severity_counts[severity] += 1

                    if len(result.matches) < max_matches:
                        # Create context (line with redaction applied)
                        context = raw_line[:200]
                        redacted_text = redaction if redact else matched_text

                        result.matches.append(
                            SensitiveMatch(
                                line_number=line_num,
                                category=category,
                                pattern_name=pattern_name,
                                matched_text=matched_text if not redact else "[REDACTED]",
                                redacted_text=redacted_text,
                                context=context if not redact else compiled.sub(redaction, context),
                                severity=severity,
                            )
                        )

        result.matches_by_category = dict(category_counts)
        result.matches_by_severity = dict(severity_counts)
        result.summary = self._generate_summary(result)

        return result

    def _should_exclude(self, matched_text: str, category: str) -> bool:
        """Check if a match should be excluded (false positive)."""
        # Skip private IPs unless explicitly included
        if category == "ip_address" and not self.include_private_ips:
            for exclude_pattern in self.EXCLUDE_PATTERNS:
                if re.match(exclude_pattern, matched_text):
                    return True
        return False

    def _generate_summary(self, result: SensitiveDataResult) -> str:
        """Generate a summary of findings."""
        if result.total_matches == 0:
            return "No sensitive data detected in the scanned log file."

        parts = [f"Found {result.total_matches} potential sensitive data matches"]

        # Severity breakdown
        high = result.matches_by_severity.get("high", 0)
        medium = result.matches_by_severity.get("medium", 0)
        low = result.matches_by_severity.get("low", 0)

        if high > 0:
            parts.append(f"{high} HIGH severity")
        if medium > 0:
            parts.append(f"{medium} MEDIUM severity")
        if low > 0:
            parts.append(f"{low} LOW severity")

        # Top categories
        if result.matches_by_category:
            top_categories = sorted(
                result.matches_by_category.items(), key=lambda x: x[1], reverse=True
            )[:3]
            cat_str = ", ".join(f"{cat} ({count})" for cat, count in top_categories)
            parts.append(f"Top categories: {cat_str}")

        return ". ".join(parts) + "."

    def redact_line(self, line: str) -> str:
        """Redact all sensitive data from a line.

        Args:
            line: The line to redact

        Returns:
            Line with all sensitive data redacted
        """
        redacted = line
        for pattern_name, (_, _, _, redaction) in self.PATTERNS.items():
            compiled = self._compiled_patterns.get(pattern_name)
            if compiled:
                redacted = compiled.sub(redaction, redacted)
        return redacted
