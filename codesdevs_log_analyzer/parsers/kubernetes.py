"""Kubernetes log parser."""

import json
import re
from datetime import datetime, timezone
from typing import Any, ClassVar

from codesdevs_log_analyzer.models import LogLevel, ParsedLogEntry
from codesdevs_log_analyzer.parsers.base import BaseLogParser
from codesdevs_log_analyzer.utils.time_utils import parse_timestamp


class KubernetesParser(BaseLogParser):
    """
    Parser for Kubernetes pod logs.

    Handles multiple formats:
    - Structured: 2026-01-15T10:30:00.123Z level=error msg="Error message" key=value
    - JSON: {"ts":"2026-01-15T10:30:00.123Z","level":"error","msg":"Error","pod":"name"}
    - Klog: I0115 10:30:00.123456 1234 file.go:123] Message
    - Simple timestamp prefix: 2026-01-15T10:30:00.123Z Message

    Also handles logs from common Kubernetes components like kube-apiserver,
    controller-manager, and kubelet.
    """

    name: ClassVar[str] = "kubernetes"
    description: ClassVar[str] = "Kubernetes pod/container log format"
    patterns: ClassVar[list[str]] = [
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*level=",
        r'^{".*"level"',
        r"^[IWEF]\d{4}\s+\d{2}:\d{2}:\d{2}",
    ]

    # Structured format: timestamp level=X msg="Y" key=value
    STRUCTURED_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
        r"(?P<kvpairs>.+)$"
    )

    # Klog format: I0115 10:30:00.123456 1234 file.go:123] message
    KLOG_PATTERN = re.compile(
        r"^(?P<level>[IWEF])(?P<date>\d{4})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
        r"(?P<pid>\d+)\s+"
        r"(?P<source>[^]]+)\]\s+"
        r"(?P<message>.*)$"
    )

    # Key-value pair pattern
    KV_PATTERN = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

    # Klog level mapping
    KLOG_LEVELS = {
        "I": LogLevel.INFO,
        "W": LogLevel.WARN,
        "E": LogLevel.ERROR,
        "F": LogLevel.FATAL,
    }

    def can_parse(self, line: str) -> bool:
        """Check if line matches Kubernetes log format."""
        if not line:
            return False

        # JSON format - must have K8s-specific indicators
        # We look for "ts" (common in K8s) or kubernetes-specific fields
        if line.startswith("{"):
            # K8s JSON typically uses "ts" for timestamp (not "timestamp")
            # or has kubernetes-specific fields like "pod", "namespace", "container"
            # Don't match generic JSON with just "level" - let JSONLParser handle those
            return (
                '"ts"' in line or '"pod"' in line or '"namespace"' in line or '"container"' in line
            )

        # Structured format with level=
        if re.match(r"^\d{4}-\d{2}-\d{2}T", line) and "level=" in line:
            return True

        # Klog format
        return bool(re.match(r"^[IWEF]\d{4}\s+\d{2}:\d{2}:\d{2}", line))

    def parse_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse a Kubernetes log line."""
        if not line:
            return None

        # Try JSON format first
        if line.startswith("{"):
            return self._parse_json_line(line, line_number)

        # Try klog format
        klog_match = self.KLOG_PATTERN.match(line)
        if klog_match:
            return self._parse_klog_line(klog_match, line, line_number)

        # Try structured format
        struct_match = self.STRUCTURED_PATTERN.match(line)
        if struct_match:
            return self._parse_structured_line(struct_match, line, line_number)

        return None

    def _parse_json_line(self, line: str, line_number: int) -> ParsedLogEntry | None:
        """Parse JSON formatted Kubernetes log."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Extract timestamp
        timestamp = None
        for ts_field in ["ts", "time", "timestamp", "@timestamp"]:
            if ts_field in data:
                timestamp = parse_timestamp(str(data[ts_field]))
                if timestamp:
                    break

        # Extract level
        level = None
        for lvl_field in ["level", "severity", "lvl"]:
            if lvl_field in data:
                level = self.normalize_level(str(data[lvl_field]))
                if level:
                    break

        # Extract message
        message = ""
        for msg_field in ["msg", "message", "log"]:
            if msg_field in data:
                message = str(data[msg_field])
                break

        if not message:
            message = json.dumps(data)

        # Build metadata from remaining fields
        excluded = {
            "ts",
            "time",
            "timestamp",
            "@timestamp",
            "level",
            "severity",
            "lvl",
            "msg",
            "message",
            "log",
        }
        metadata = {k: v for k, v in data.items() if k not in excluded}
        metadata["format"] = "json"

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _parse_klog_line(
        self,
        match: re.Match[str],
        line: str,
        line_number: int,
    ) -> ParsedLogEntry:
        """Parse klog formatted line."""
        groups = match.groupdict()

        # Parse timestamp (need to add year)
        timestamp = self._parse_klog_timestamp(groups["date"], groups["time"])

        # Get level
        level = self.KLOG_LEVELS.get(groups["level"], LogLevel.INFO)

        # Get message
        message = groups.get("message", "").strip()

        # Build metadata
        metadata: dict[str, Any] = {
            "format": "klog",
            "source": groups.get("source"),
        }

        pid = groups.get("pid")
        if pid:
            metadata["pid"] = int(pid)

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _parse_structured_line(
        self,
        match: re.Match[str],
        line: str,
        line_number: int,
    ) -> ParsedLogEntry:
        """Parse structured key=value format."""
        groups = match.groupdict()

        # Parse timestamp
        timestamp = parse_timestamp(groups.get("timestamp", ""))

        # Parse key-value pairs
        kvpairs = groups.get("kvpairs", "")
        kv_dict = self._parse_kv_pairs(kvpairs)

        # Extract level
        level_str = kv_dict.pop("level", None) or kv_dict.pop("lvl", None)
        level = self.normalize_level(level_str) if level_str else None

        # Extract message
        message = kv_dict.pop("msg", None) or kv_dict.pop("message", None) or kvpairs

        # Remaining pairs are metadata
        metadata = kv_dict
        metadata["format"] = "structured"

        return self.create_entry(
            line_number=line_number,
            raw_line=line,
            message=message,
            timestamp=timestamp,
            level=level,
            metadata=metadata,
        )

    def _parse_kv_pairs(self, text: str) -> dict[str, str]:
        """Parse key=value pairs from text."""
        result: dict[str, str] = {}

        for match in self.KV_PATTERN.finditer(text):
            key = match.group(1)
            # Value is either quoted (group 2) or unquoted (group 3)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            result[key] = value

        return result

    def _parse_klog_timestamp(self, date_str: str, time_str: str) -> datetime | None:
        """Parse klog timestamp (MMDD HH:MM:SS.microseconds)."""
        if not date_str or not time_str:
            return None

        try:
            month = int(date_str[:2])
            day = int(date_str[2:4])

            time_parts = time_str.split(".")
            hms = time_parts[0]
            hour, minute, second = map(int, hms.split(":"))

            microsecond = 0
            if len(time_parts) > 1:
                # Pad or truncate to 6 digits
                frac = time_parts[1][:6].ljust(6, "0")
                microsecond = int(frac)

            return datetime(
                self.default_year,
                month,
                day,
                hour,
                minute,
                second,
                microsecond,
                tzinfo=timezone.utc,
            )
        except (ValueError, TypeError):
            return None
