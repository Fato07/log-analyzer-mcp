"""Output formatting utilities for log analysis results."""

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from codesdevs_log_analyzer.models import (
    ErrorGroup,
    ExtractErrorsResult,
    LogLevel,
    LogSummary,
    ParsedLogEntry,
    ParseResult,
    SearchResult,
    TailResult,
)
from codesdevs_log_analyzer.utils.time_utils import format_timestamp, time_ago

# ============================================================================
# Constants
# ============================================================================

# Default context limit for AI consumption (characters)
DEFAULT_CONTEXT_LIMIT = 100000  # ~25K tokens
MAX_LINE_LENGTH = 500  # Truncate individual lines


# ============================================================================
# JSON Formatting
# ============================================================================


def format_as_json(data: BaseModel | dict[str, Any] | list[Any]) -> str:
    """
    Format data as JSON string.

    Handles Pydantic models, dicts, and lists with datetime serialization.

    Args:
        data: Data to format

    Returns:
        JSON string
    """
    if isinstance(data, BaseModel):
        return data.model_dump_json(indent=2)

    def json_serializer(obj: Any) -> str:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, LogLevel):
            return obj.value
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    return json.dumps(data, indent=2, default=json_serializer)


# ============================================================================
# Markdown Formatting
# ============================================================================


def format_as_markdown(data: BaseModel | dict[str, Any]) -> str:
    """
    Format data as readable Markdown for AI context.

    Auto-detects data type and applies appropriate formatting.

    Args:
        data: Data to format

    Returns:
        Markdown formatted string
    """
    if isinstance(data, ParseResult):
        return _format_parse_result_md(data)

    if isinstance(data, SearchResult):
        return _format_search_result_md(data)

    if isinstance(data, ExtractErrorsResult):
        return _format_errors_result_md(data)

    if isinstance(data, LogSummary):
        return _format_summary_md(data)

    if isinstance(data, TailResult):
        return _format_tail_result_md(data)

    if isinstance(data, BaseModel):
        return _format_generic_model_md(data)

    if isinstance(data, dict):
        return _format_dict_md(data)

    return str(data)


def _format_parse_result_md(result: ParseResult) -> str:
    """Format ParseResult as Markdown."""
    lines = [
        "## Log Parse Results",
        "",
        f"**File:** `{result.file_path}`",
        f"**Format:** {result.format_detection.detected_format.value} "
        f"(confidence: {result.format_detection.confidence:.0%})",
        f"**Lines:** {result.parsed_lines:,} / {result.total_lines:,} parsed",
        "",
    ]

    # Time range
    if result.time_range_start and result.time_range_end:
        lines.append(
            f"**Time Range:** {format_timestamp(result.time_range_start, 'human')} → "
            f"{format_timestamp(result.time_range_end, 'human')}"
        )
        lines.append("")

    # Level distribution
    if result.level_counts:
        lines.append("### Log Levels")
        lines.append("")
        for level, count in sorted(result.level_counts.items(), key=lambda x: -x[1]):
            bar = "█" * min(50, count * 50 // max(result.level_counts.values()))
            lines.append(f"- **{level}:** {count:,} {bar}")
        lines.append("")

    # Sample entries
    if result.entries:
        lines.append("### Sample Entries")
        lines.append("")
        for entry in result.entries[:10]:
            lines.append(_format_entry_md(entry))
            lines.append("")

        if len(result.entries) > 10:
            lines.append(f"_... and {len(result.entries) - 10} more entries_")

    return "\n".join(lines)


def _format_search_result_md(result: SearchResult) -> str:
    """Format SearchResult as Markdown."""
    lines = [
        "## Search Results",
        "",
        f"**File:** `{result.file_path}`",
        f"**Pattern:** `{result.pattern}`",
        f"**Matches:** {result.total_matches:,}",
        "",
    ]

    if result.truncated:
        lines.append("_⚠️ Results truncated_")
        lines.append("")

    for i, match in enumerate(result.matches, 1):
        lines.append(f"### Match {i} (Line {match.entry.line_number})")
        lines.append("")

        # Context before
        for ctx_line in match.context_before:
            lines.append(f"    {_truncate_line(ctx_line)}")

        # The match itself (highlighted)
        lines.append(f">>> {_truncate_line(match.entry.raw_line)}")

        # Context after
        for ctx_line in match.context_after:
            lines.append(f"    {_truncate_line(ctx_line)}")

        lines.append("")

    return "\n".join(lines)


def _format_errors_result_md(result: ExtractErrorsResult) -> str:
    """Format ExtractErrorsResult as Markdown."""
    lines = [
        "## Error Extraction Results",
        "",
        f"**File:** `{result.file_path}`",
        f"**Total Errors:** {result.total_errors:,}",
        f"**Total Warnings:** {result.total_warnings:,}",
        f"**Unique Error Types:** {result.unique_errors:,}",
        "",
    ]

    if result.error_groups:
        lines.append("### Error Groups")
        lines.append("")

        for i, group in enumerate(result.error_groups, 1):
            lines.append(f"#### {i}. {_truncate_line(group.message_template, 80)}")
            lines.append("")
            lines.append(f"- **Count:** {group.count:,}")

            if group.first_seen:
                lines.append(f"- **First seen:** {time_ago(group.first_seen)}")
            if group.last_seen:
                lines.append(f"- **Last seen:** {time_ago(group.last_seen)}")

            if group.stack_trace:
                lines.append("")
                lines.append("```")
                # Truncate long stack traces
                trace_lines = group.stack_trace.split("\n")[:20]
                lines.extend(trace_lines)
                if len(group.stack_trace.split("\n")) > 20:
                    lines.append("... (truncated)")
                lines.append("```")

            lines.append("")

    return "\n".join(lines)


def _format_summary_md(summary: LogSummary) -> str:
    """Format LogSummary as Markdown."""
    lines = [
        "## Log Summary",
        "",
        f"**File:** `{summary.file_path}`",
        f"**Total Lines:** {summary.total_lines:,}",
        f"**Parsed Lines:** {summary.parsed_lines:,}",
    ]

    if summary.time_span:
        lines.append(f"**Time Span:** {summary.time_span}")

    lines.append("")

    # Level distribution
    if summary.level_distribution:
        lines.append("### Log Level Distribution")
        lines.append("")
        total = sum(summary.level_distribution.values())
        for level, count in sorted(summary.level_distribution.items(), key=lambda x: -x[1]):
            pct = count / total * 100 if total > 0 else 0
            lines.append(f"- **{level}:** {count:,} ({pct:.1f}%)")
        lines.append("")

    # Activity pattern
    if summary.activity_pattern:
        lines.append("### Activity Pattern")
        lines.append("")
        lines.append(summary.activity_pattern)
        lines.append("")

    # Top errors
    if summary.top_errors:
        lines.append("### Top Errors")
        lines.append("")
        for i, error in enumerate(summary.top_errors[:5], 1):
            lines.append(f"{i}. **{error.count}x** - {_truncate_line(error.message_template, 60)}")
        lines.append("")

    # Recommendations
    if summary.recommendations:
        lines.append("### Recommendations")
        lines.append("")
        for rec in summary.recommendations:
            lines.append(f"- {rec}")
        lines.append("")

    return "\n".join(lines)


def _format_tail_result_md(result: TailResult) -> str:
    """Format TailResult as Markdown."""
    lines = [
        "## Recent Log Entries",
        "",
        f"**File:** `{result.file_path}`",
        f"**Lines Returned:** {result.lines_returned:,}",
        "",
    ]

    for entry in result.entries:
        lines.append(_format_entry_md(entry))
        lines.append("")

    return "\n".join(lines)


def _format_entry_md(entry: ParsedLogEntry) -> str:
    """Format a single ParsedLogEntry as Markdown."""
    parts = [f"**[{entry.line_number}]**"]

    if entry.timestamp:
        parts.append(f"_{format_timestamp(entry.timestamp, 'compact')}_")

    if entry.level:
        level_emoji = _get_level_emoji(entry.level)
        parts.append(f"{level_emoji} {entry.level.value}")

    parts.append(f"`{_truncate_line(entry.message)}`")

    return " ".join(parts)


def _format_generic_model_md(model: BaseModel) -> str:
    """Format any Pydantic model as Markdown."""
    lines = [f"## {model.__class__.__name__}", ""]

    for field_name, field_value in model.model_dump().items():
        if field_value is None:
            continue

        formatted_name = field_name.replace("_", " ").title()

        if isinstance(field_value, list):
            lines.append(f"**{formatted_name}:** {len(field_value)} items")
        elif isinstance(field_value, dict):
            lines.append(f"**{formatted_name}:** {len(field_value)} entries")
        else:
            lines.append(f"**{formatted_name}:** {field_value}")

    return "\n".join(lines)


def _format_dict_md(data: dict[str, Any]) -> str:
    """Format dictionary as Markdown."""
    lines = []
    for key, value in data.items():
        formatted_key = key.replace("_", " ").title()
        if isinstance(value, list):
            lines.append(f"**{formatted_key}:** {len(value)} items")
        elif isinstance(value, dict):
            lines.append(f"**{formatted_key}:** {len(value)} entries")
        else:
            lines.append(f"**{formatted_key}:** {value}")
    return "\n".join(lines)


# ============================================================================
# Helper Functions
# ============================================================================


def _truncate_line(line: str, max_length: int = MAX_LINE_LENGTH) -> str:
    """Truncate line to maximum length."""
    if len(line) <= max_length:
        return line
    return line[: max_length - 3] + "..."


def _get_level_emoji(level: LogLevel) -> str:
    """Get emoji for log level."""
    emoji_map = {
        LogLevel.TRACE: "🔍",
        LogLevel.DEBUG: "🐛",
        LogLevel.INFO: "ℹ️",
        LogLevel.NOTICE: "📋",
        LogLevel.WARN: "⚠️",
        LogLevel.WARNING: "⚠️",
        LogLevel.ERROR: "❌",
        LogLevel.CRITICAL: "🔴",
        LogLevel.FATAL: "💀",
        LogLevel.EMERGENCY: "🚨",
    }
    return emoji_map.get(level, "•")


# ============================================================================
# Context Truncation
# ============================================================================


def truncate_for_context(
    content: str,
    max_chars: int = DEFAULT_CONTEXT_LIMIT,
    preserve_structure: bool = True,
) -> tuple[str, bool]:
    """
    Truncate content to fit within AI context limits.

    Tries to preserve meaningful structure when truncating.

    Args:
        content: Content to potentially truncate
        max_chars: Maximum character count
        preserve_structure: Whether to try to preserve Markdown structure

    Returns:
        Tuple of (truncated_content, was_truncated)
    """
    if len(content) <= max_chars:
        return content, False

    if not preserve_structure:
        return content[: max_chars - 50] + "\n\n_... (truncated)_", True

    # Try to truncate at section boundaries
    lines = content.split("\n")
    result_lines: list[str] = []
    current_length = 0

    for line in lines:
        line_length = len(line) + 1  # +1 for newline
        if current_length + line_length > max_chars - 100:
            # Try to stop at a section header
            if line.startswith("#") or line.startswith("---"):
                result_lines.append(line)
            break
        result_lines.append(line)
        current_length += line_length

    result = "\n".join(result_lines)
    result += "\n\n_... (truncated to fit context window)_"

    return result, True


def format_entries_compact(
    entries: list[ParsedLogEntry],
    max_entries: int = 50,
    max_line_length: int = 200,
) -> str:
    """
    Format log entries in a compact format for minimal token usage.

    Args:
        entries: Log entries to format
        max_entries: Maximum entries to include
        max_line_length: Maximum line length

    Returns:
        Compact formatted string
    """
    lines = []
    for entry in entries[:max_entries]:
        parts = [f"[{entry.line_number}]"]

        if entry.timestamp:
            parts.append(entry.timestamp.strftime("%H:%M:%S"))

        if entry.level:
            parts.append(entry.level.value[:3])  # Abbreviated level

        msg = entry.message[:max_line_length]
        if len(entry.message) > max_line_length:
            msg += "..."
        parts.append(msg)

        lines.append(" ".join(parts))

    if len(entries) > max_entries:
        lines.append(f"... and {len(entries) - max_entries} more entries")

    return "\n".join(lines)


def format_error_group_compact(group: ErrorGroup) -> str:
    """Format error group compactly."""
    msg = _truncate_line(group.message_template, 60)
    return f"{group.count}x: {msg}"
