"""FastMCP server for log analysis tools."""

import json
import os
import re
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from codesdevs_log_analyzer.analyzers import (
    Correlator,
    ErrorExtractor,
    LogWatcher,
    PatternSuggester,
    Summarizer,
)
from codesdevs_log_analyzer.models import (
    LogFormat,
    ParsedLogEntry,
)
from codesdevs_log_analyzer.parsers import (
    PARSER_REGISTRY,
    detect_format,
    get_parser,
)
from codesdevs_log_analyzer.utils import (
    read_tail,
    stream_file,
)

# Initialize FastMCP server
mcp = FastMCP(
    "log-analyzer-mcp",
    instructions="MCP server for intelligent log file analysis and debugging assistance",
)


# =============================================================================
# Helper Functions
# =============================================================================


def handle_tool_error(error: Exception, file_path: str) -> str:
    """Generate helpful error message."""
    if isinstance(error, FileNotFoundError):
        return f"Error: File not found: {file_path}\nPlease check the path and try again."
    if isinstance(error, PermissionError):
        return f"Error: Permission denied: {file_path}\nCheck file permissions."
    if isinstance(error, UnicodeDecodeError):
        return "Error: Unable to decode file. Try specifying encoding or check if file is binary."
    if isinstance(error, IsADirectoryError):
        return f"Error: {file_path} is a directory, not a file."
    return f"Error: {type(error).__name__}: {str(error)}"


def get_file_info(file_path: str) -> dict[str, Any]:
    """Get basic file information."""
    stat = os.stat(file_path)
    return {
        "size_bytes": stat.st_size,
        "size_human": _format_size(stat.st_size),
    }


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable form."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes //= 1024
    return f"{size_bytes:.1f} TB"


def _format_level_chart(level_counts: dict[str, int], total: int) -> str:
    """Format log level distribution as ASCII chart."""
    if not level_counts or total == 0:
        return "No log levels detected"

    lines = []
    max_label_len = max(len(level) for level in level_counts)

    for level, count in sorted(level_counts.items(), key=lambda x: -x[1]):
        pct = (count / total) * 100
        bar_len = int(pct / 5)  # 20 chars max
        bar = "█" * bar_len + "░" * (20 - bar_len)
        lines.append(f"{level:<{max_label_len}}  {bar}  {count:,} ({pct:.1f}%)")

    return "\n".join(lines)


def _entry_to_dict(entry: ParsedLogEntry) -> dict[str, Any]:
    """Convert ParsedLogEntry to JSON-serializable dict."""
    return {
        "line_number": entry.line_number,
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "level": entry.level.value if entry.level else None,
        "message": entry.message[:500],  # Truncate long messages
        "metadata": entry.metadata,
    }


# =============================================================================
# Tool 1: log_analyzer_parse (P0)
# =============================================================================


@mcp.tool()
def log_analyzer_parse(
    file_path: str,
    format_hint: str | None = None,
    max_lines: int = 10000,
    response_format: str = "markdown",
) -> str:
    """
    Parse and analyze a log file, detecting its format and extracting metadata.

    Args:
        file_path: Path to the log file to analyze
        format_hint: Force specific format (syslog, apache_access, apache_error, jsonl,
                     docker, python, java, kubernetes, generic) or None for auto-detect
        max_lines: Maximum lines to parse (100-100000, default 10000)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Analysis results including detected format, time range, level distribution,
        and sample entries.
    """
    try:
        # Validate file exists
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        file_info = get_file_info(file_path)

        # Get parser
        if format_hint and format_hint.lower() != "auto":
            try:
                parser = get_parser(format_hint.lower())
                confidence = 1.0  # User specified
            except ValueError as e:
                return f"Error: {e}\nAvailable formats: {', '.join(PARSER_REGISTRY.keys())}"
        else:
            parser, confidence = detect_format(file_path)

        # Parse entries
        entries: list[ParsedLogEntry] = []
        level_counts: dict[str, int] = {}
        time_start: datetime | None = None
        time_end: datetime | None = None
        total_lines = 0
        parsed_lines = 0

        for line_num, line in stream_file(file_path, max_lines=max_lines):
            total_lines = line_num
            entry = parser.parse_line(line, line_num)
            if entry:
                parsed_lines += 1
                entries.append(entry)

                # Track levels
                if entry.level:
                    level_str = (
                        entry.level.value if hasattr(entry.level, "value") else str(entry.level)
                    )
                    level_counts[level_str] = level_counts.get(level_str, 0) + 1

                # Track time range
                if entry.timestamp:
                    if time_start is None or entry.timestamp < time_start:
                        time_start = entry.timestamp
                    if time_end is None or entry.timestamp > time_end:
                        time_end = entry.timestamp

        # Prepare result
        result = {
            "file": file_path,
            "format": {
                "name": parser.name,
                "confidence": round(confidence, 2),
            },
            "file_size": file_info,
            "lines": {
                "total": total_lines,
                "parsed": parsed_lines,
                "parse_rate": round(parsed_lines / total_lines * 100, 1) if total_lines > 0 else 0,
            },
            "time_range": {
                "start": time_start.isoformat() if time_start else None,
                "end": time_end.isoformat() if time_end else None,
            },
            "levels": level_counts,
            "sample_entries": {
                "first_5": [_entry_to_dict(e) for e in entries[:5]],
                "last_5": [_entry_to_dict(e) for e in entries[-5:]] if len(entries) > 5 else [],
            },
        }

        if response_format.lower() == "json":
            return json.dumps(result, indent=2)

        # Markdown format
        md = f"""## Log Analysis Results

**File:** `{file_path}`
**Format:** {parser.name} (confidence: {confidence:.0%})
**Size:** {file_info["size_human"]}

### Lines Processed
- **Total:** {total_lines:,}
- **Parsed:** {parsed_lines:,} ({round(parsed_lines / total_lines * 100, 1) if total_lines > 0 else 0}%)

### Time Range
- **Start:** {time_start.isoformat() if time_start else "N/A"}
- **End:** {time_end.isoformat() if time_end else "N/A"}

### Level Distribution
```
{_format_level_chart(level_counts, parsed_lines)}
```

### Sample Entries (First 5)
"""
        for entry in entries[:5]:
            ts = entry.timestamp.isoformat() if entry.timestamp else "N/A"
            level = entry.level.value if entry.level else "N/A"
            md += f"- **Line {entry.line_number}** [{level}] {ts}\n  `{entry.message[:100]}{'...' if len(entry.message) > 100 else ''}`\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 2: log_analyzer_search (P0)
# =============================================================================


@mcp.tool()
def log_analyzer_search(
    file_path: str,
    pattern: str,
    is_regex: bool = False,
    case_sensitive: bool = False,
    context_lines: int = 3,
    max_matches: int = 50,
    level_filter: str | None = None,
    response_format: str = "markdown",
) -> str:
    """
    Search for patterns in a log file with context lines.

    Args:
        file_path: Path to the log file to search
        pattern: Search pattern (regex or plain text)
        is_regex: Treat pattern as regex (default: False, plain text)
        case_sensitive: Case-sensitive search (default: False)
        context_lines: Lines of context before/after match (0-10, default: 3)
        max_matches: Maximum matches to return (1-200, default: 50)
        level_filter: Filter by log level (ERROR, WARN, INFO, DEBUG)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Search results with matches and surrounding context.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Compile pattern
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            if is_regex:
                regex = re.compile(pattern, flags)
            else:
                regex = re.compile(re.escape(pattern), flags)
        except re.error as e:
            return f"Error: Invalid regex pattern: {e}"

        # Get parser for level filtering
        parser, _ = detect_format(file_path)

        # Normalize level filter
        level_filter_upper = level_filter.upper() if level_filter else None

        # Search with context
        matches: list[dict[str, Any]] = []
        line_buffer: list[tuple[int, str]] = []
        total_matches = 0

        for line_num, line in stream_file(file_path):
            # Maintain context buffer
            line_buffer.append((line_num, line))
            if len(line_buffer) > context_lines * 2 + 1:
                line_buffer.pop(0)

            # Check for match
            if regex.search(line):
                # Parse entry for level filtering
                entry = parser.parse_line(line, line_num)

                if level_filter_upper and entry and entry.level:
                    entry_level = (
                        entry.level.value if hasattr(entry.level, "value") else str(entry.level)
                    )
                    if entry_level.upper() != level_filter_upper:
                        continue

                total_matches += 1

                if len(matches) < max_matches:
                    # Get context before
                    context_before = [
                        line
                        for n, line in line_buffer[:-1]
                        if n < line_num and n >= line_num - context_lines
                    ]

                    matches.append(
                        {
                            "line_number": line_num,
                            "line": line,
                            "context_before": context_before,
                            "context_after": [],  # Will be filled after
                            "timestamp": entry.timestamp.isoformat()
                            if entry and entry.timestamp
                            else None,
                            "level": entry.level.value if entry and entry.level else None,
                        }
                    )

        # Fill context_after (simplified - read file again for context)
        if matches and context_lines > 0:
            all_lines = dict(stream_file(file_path))
            for match in matches:
                ln = match["line_number"]
                match["context_after"] = [
                    all_lines.get(ln + i, "")
                    for i in range(1, context_lines + 1)
                    if ln + i in all_lines
                ]

        result = {
            "file": file_path,
            "pattern": pattern,
            "is_regex": is_regex,
            "case_sensitive": case_sensitive,
            "total_matches": total_matches,
            "matches_shown": len(matches),
            "truncated": total_matches > max_matches,
            "matches": matches,
        }

        if response_format.lower() == "json":
            return json.dumps(result, indent=2)

        # Markdown format
        md = f"""## Search Results

**File:** `{file_path}`
**Pattern:** `{pattern}` {"(regex)" if is_regex else "(text)"}
**Matches:** {len(matches)} shown / {total_matches} total{" (truncated)" if total_matches > max_matches else ""}

"""
        for i, match in enumerate(matches, 1):
            md += f"### Match {i} - Line {match['line_number']}\n"
            if match.get("timestamp") or match.get("level"):
                md += f"*{match.get('level', '')} | {match.get('timestamp', '')}*\n\n"

            md += "```\n"
            for ctx in match.get("context_before", []):
                md += f"  {ctx}\n"
            md += f"> {match['line']}\n"
            for ctx in match.get("context_after", []):
                md += f"  {ctx}\n"
            md += "```\n\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 3: log_analyzer_extract_errors (P0)
# =============================================================================


@mcp.tool()
def log_analyzer_extract_errors(
    file_path: str,
    include_warnings: bool = False,
    group_similar: bool = True,
    max_errors: int = 100,
    response_format: str = "markdown",
) -> str:
    """
    Extract all errors and exceptions from a log file with stack traces.

    Args:
        file_path: Path to the log file
        include_warnings: Include WARN level entries (default: False)
        group_similar: Group similar error messages (default: True)
        max_errors: Maximum errors to return (1-500, default: 100)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Extracted errors grouped by similarity with occurrence counts,
        timestamps, and sample stack traces.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Detect format and get parser
        parser, _ = detect_format(file_path)

        # Extract errors using analyzer
        extractor = ErrorExtractor(
            include_warnings=include_warnings,
            max_errors=max_errors,
            group_similar=group_similar,
        )

        result = extractor.analyze_file(parser, file_path)

        output = {
            "file": file_path,
            "total_errors": result.total_errors,
            "total_warnings": result.total_warnings,
            "unique_errors": result.unique_errors,
            "time_range": {
                "start": result.time_range[0].isoformat() if result.time_range[0] else None,
                "end": result.time_range[1].isoformat() if result.time_range[1] else None,
            },
            "error_groups": [
                {
                    "template": g.template,
                    "count": g.count,
                    "first_seen": g.first_seen.isoformat() if g.first_seen else None,
                    "last_seen": g.last_seen.isoformat() if g.last_seen else None,
                    "levels": list(g.levels),
                    "sample_entries": [
                        {
                            "line_number": e.line_number,
                            "message": e.message[:300],
                        }
                        for e in g.sample_entries[:3]
                    ],
                    "stack_trace": g.stack_trace[:1000] if g.stack_trace else None,
                }
                for g in result.error_groups
            ],
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Error Extraction Results

**File:** `{file_path}`
**Total Errors:** {result.total_errors:,}
**Total Warnings:** {result.total_warnings:,}
**Unique Error Types:** {result.unique_errors}

"""
        if result.time_range[0] and result.time_range[1]:
            md += f"**Time Range:** {result.time_range[0].isoformat()} to {result.time_range[1].isoformat()}\n\n"

        md += "### Error Groups\n\n"

        for i, group in enumerate(result.error_groups[:20], 1):
            md += f"#### {i}. **{group.template[:100]}{'...' if len(group.template) > 100 else ''}**\n"
            md += f"- **Occurrences:** {group.count}\n"
            if group.first_seen:
                md += f"- **First seen:** {group.first_seen.isoformat()}\n"
            if group.last_seen:
                md += f"- **Last seen:** {group.last_seen.isoformat()}\n"
            if group.levels:
                md += f"- **Levels:** {', '.join(group.levels)}\n"

            if group.stack_trace:
                md += f"\n```\n{group.stack_trace[:500]}{'...' if len(group.stack_trace) > 500 else ''}\n```\n"
            md += "\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 4: log_analyzer_summarize (P1)
# =============================================================================


@mcp.tool()
def log_analyzer_summarize(
    file_path: str,
    focus: str = "all",
    max_lines: int = 10000,
    response_format: str = "markdown",
) -> str:
    """
    Generate a debugging summary of a log file.

    Args:
        file_path: Path to the log file
        focus: Focus area - 'errors', 'performance', 'security', or 'all' (default)
        max_lines: Maximum lines to analyze (100-100000, default: 10000)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Summary including file overview, level distribution, top errors,
        anomalies detected, and recommended investigation areas.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        file_info = get_file_info(file_path)
        parser, confidence = detect_format(file_path)

        # Use summarizer analyzer - requires file_path in constructor
        summarizer = Summarizer(
            file_path=file_path,
            include_performance=(focus == "all" or focus == "performance"),
            include_security=(focus == "all" or focus == "security"),
            detected_format=parser.format if hasattr(parser, "format") else LogFormat.AUTO,
        )
        summary = summarizer.summarize_file(parser, max_lines=max_lines)

        # Count total raw lines for consistency with parse tool
        total_raw_lines = 0
        for line_num, _ in stream_file(file_path, max_lines=max_lines):
            total_raw_lines = line_num

        output = {
            "file": file_path,
            "format": {"name": parser.name, "confidence": round(confidence, 2)},
            "file_size": file_info,
            "lines": {
                "total": total_raw_lines,
                "parsed": summary.total_entries,
            },
            "time_range": {
                "start": summary.time_range.start.isoformat() if summary.time_range.start else None,
                "end": summary.time_range.end.isoformat() if summary.time_range.end else None,
            },
            "level_distribution": summary.level_distribution,
            "top_errors": [
                {
                    "message": e.template[:200],
                    "count": e.count,
                    "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                }
                for e in summary.top_errors[:10]
            ],
            "anomalies": [
                {
                    "type": a.type,
                    "description": a.description,
                    "severity": a.severity,
                }
                for a in summary.anomalies
            ],
            "recommendations": summary.recommendations,
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Log Summary

**File:** `{file_path}`
**Format:** {parser.name} (confidence: {confidence:.0%})
**Size:** {file_info["size_human"]}

### Overview
- **Total Lines:** {total_raw_lines:,}
- **Parsed:** {summary.total_entries:,}
"""
        time_start = summary.time_range.start
        time_end = summary.time_range.end
        if time_start and time_end:
            duration = (time_end - time_start).total_seconds()
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            md += f"- **Time Span:** {hours}h {minutes}m\n"
            md += f"- **From:** {time_start.isoformat()}\n"
            md += f"- **To:** {time_end.isoformat()}\n"

        md += f"""
### Level Distribution
```
{_format_level_chart(summary.level_distribution, summary.total_entries)}
```

### Top Errors
"""
        for i, error in enumerate(summary.top_errors[:5], 1):
            md += f"{i}. **{error.template[:80]}{'...' if len(error.template) > 80 else ''}** ({error.count} occurrences)\n"

        if summary.anomalies:
            md += "\n### Anomalies Detected\n"
            for anomaly in summary.anomalies:
                severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(
                    anomaly.severity, "⚪"
                )
                md += f"- {severity_emoji} **{anomaly.type}:** {anomaly.description}\n"

        if summary.recommendations:
            md += "\n### Recommendations\n"
            for rec in summary.recommendations:
                md += f"- {rec}\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 5: log_analyzer_tail (P1)
# =============================================================================


@mcp.tool()
def log_analyzer_tail(
    file_path: str,
    lines: int = 100,
    level_filter: str | None = None,
    response_format: str = "markdown",
) -> str:
    """
    Get the most recent log entries from a file.

    Args:
        file_path: Path to the log file
        lines: Number of lines to return (1-1000, default: 100)
        level_filter: Filter by log level (ERROR, WARN, INFO, DEBUG)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        The last N log entries, parsed and formatted.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Read tail lines - returns list[tuple[int, str]] (line_number, line_content)
        tail_lines = read_tail(file_path, lines)

        # Parse with detected format
        parser, _ = detect_format(file_path)

        # Normalize level filter
        level_filter_upper = level_filter.upper() if level_filter else None

        entries: list[dict[str, Any]] = []
        for line_num, line in tail_lines:  # Unpack tuple directly
            entry = parser.parse_line(line, line_num)
            if entry:
                # Apply level filter
                if level_filter_upper:
                    entry_level = entry.level.value if entry and entry.level else None
                    if entry_level and entry_level.upper() != level_filter_upper:
                        continue

                entries.append(
                    {
                        "line_number": line_num,
                        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                        "level": entry.level.value if entry.level else None,
                        "message": entry.message,
                    }
                )

        result = {
            "file": file_path,
            "lines_requested": lines,
            "lines_returned": len(entries),
            "level_filter": level_filter,
            "entries": entries,
        }

        if response_format.lower() == "json":
            return json.dumps(result, indent=2)

        # Markdown format
        md = f"""## Recent Log Entries

**File:** `{file_path}`
**Lines:** {len(entries)} of {lines} requested
"""
        if level_filter:
            md += f"**Filter:** {level_filter}\n"

        md += "\n```\n"
        for entry_data in entries:
            ts = entry_data["timestamp"][:19] if entry_data["timestamp"] else "N/A"
            level = entry_data["level"] or "---"
            msg = entry_data["message"][:120]
            md += f"[{ts}] {level:8} {msg}\n"
        md += "```\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 6: log_analyzer_correlate (P2)
# =============================================================================


@mcp.tool()
def log_analyzer_correlate(
    file_path: str,
    anchor_pattern: str,
    window_seconds: int = 60,
    max_anchors: int = 10,
    response_format: str = "markdown",
) -> str:
    """
    Correlate events around anchor points in a log file.

    Args:
        file_path: Path to the log file
        anchor_pattern: Pattern to anchor correlation around (regex)
        window_seconds: Time window in seconds around anchor (1-3600, default: 60)
        max_anchors: Maximum anchor points to analyze (1-50, default: 10)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Correlated events around each anchor point, showing what happened
        before and after the anchor event.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Validate anchor pattern (Correlator will compile it)
        try:
            re.compile(anchor_pattern, re.IGNORECASE)
        except re.error as e:
            return f"Error: Invalid regex pattern: {e}"

        parser, _ = detect_format(file_path)

        # Use correlator analyzer - requires anchor_pattern in constructor
        correlator = Correlator(
            anchor_pattern=anchor_pattern,
            window_before=window_seconds,
            window_after=window_seconds,
            max_anchors=max_anchors,
            regex=True,
            case_sensitive=False,
        )

        result = correlator.correlate_file(
            parser=parser,
            file_path=file_path,
        )

        output = {
            "file": file_path,
            "anchor_pattern": anchor_pattern,
            "window_seconds": window_seconds,
            "anchors_found": len(result.windows),
            "common_precursors": result.common_precursors[:5],
            "windows": [
                {
                    "anchor_time": w.anchor_entry.timestamp.isoformat()
                    if w.anchor_entry and w.anchor_entry.timestamp
                    else None,
                    "anchor_line": w.anchor_entry.line_number if w.anchor_entry else None,
                    "anchor_message": w.anchor_entry.message[:200] if w.anchor_entry else None,
                    "events_before": len(w.events_before),
                    "events_after": len(w.events_after),
                    "related_errors": [
                        {"line": e.line_number, "message": e.message[:100]}
                        for e in w.related_errors[:3]
                    ],
                }
                for w in result.windows
            ],
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Correlation Results

**File:** `{file_path}`
**Anchor Pattern:** `{anchor_pattern}`
**Time Window:** ±{window_seconds} seconds
**Anchors Found:** {len(result.windows)}

"""
        if result.common_precursors:
            md += "### Common Precursor Patterns\n"
            for precursor in result.common_precursors[:5]:
                md += f"- `{precursor}`\n"
            md += "\n"

        for i, window in enumerate(result.windows, 1):
            md += f"### Anchor {i}\n"
            if window.anchor_entry:
                md += f"**Line {window.anchor_entry.line_number}:** `{window.anchor_entry.message[:100]}`\n"
            if window.anchor_entry and window.anchor_entry.timestamp:
                md += f"**Time:** {window.anchor_entry.timestamp.isoformat()}\n"
            md += f"- Events before: {len(window.events_before)}\n"
            md += f"- Events after: {len(window.events_after)}\n"

            if window.related_errors:
                md += "\n**Related Errors:**\n"
                for err in window.related_errors[:3]:
                    md += f"- Line {err.line_number}: `{err.message[:80]}`\n"
            md += "\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 7: log_analyzer_diff (P2)
# =============================================================================


@mcp.tool()
def log_analyzer_diff(
    file_path_a: str,
    file_path_b: str | None = None,
    time_range_a_start: str | None = None,
    time_range_a_end: str | None = None,
    time_range_b_start: str | None = None,
    time_range_b_end: str | None = None,
    response_format: str = "markdown",
) -> str:
    """
    Compare log files or time periods within a log file.

    Args:
        file_path_a: First log file path
        file_path_b: Second log file path (optional - for comparing two files)
        time_range_a_start: Start time for first period (ISO format, for time comparison)
        time_range_a_end: End time for first period (ISO format)
        time_range_b_start: Start time for second period (ISO format)
        time_range_b_end: End time for second period (ISO format)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Comparison showing new errors, resolved errors, and volume changes.
    """
    try:
        if not os.path.isfile(file_path_a):
            return handle_tool_error(FileNotFoundError(), file_path_a)

        if file_path_b and not os.path.isfile(file_path_b):
            return handle_tool_error(FileNotFoundError(), file_path_b)

        parser_a, _ = detect_format(file_path_a)

        # Parse time ranges
        def parse_time(ts: str | None) -> datetime | None:
            if not ts:
                return None
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return None

        t_a_start = parse_time(time_range_a_start)
        t_a_end = parse_time(time_range_a_end)
        t_b_start = parse_time(time_range_b_start)
        t_b_end = parse_time(time_range_b_end)

        # Extract errors from both sources
        def extract_errors_filtered(
            file_path: str,
            parser: Any,
            start: datetime | None,
            end: datetime | None,
        ) -> dict[str, int]:
            """Extract error patterns with optional time filtering."""
            extractor = ErrorExtractor(include_warnings=False, group_similar=True)
            errors: dict[str, int] = {}

            for entry in parser.parse_file(file_path):
                # Time filter
                if start and entry.timestamp and entry.timestamp < start:
                    continue
                if end and entry.timestamp and entry.timestamp > end:
                    continue

                # Process entry
                extractor.process_entry(entry)

            result = extractor.finalize()
            for group in result.error_groups:
                errors[group.template] = group.count

            return errors

        errors_a = extract_errors_filtered(file_path_a, parser_a, t_a_start, t_a_end)

        if file_path_b:
            parser_b, _ = detect_format(file_path_b)
            errors_b = extract_errors_filtered(file_path_b, parser_b, t_b_start, t_b_end)
            comparison_desc = f"{file_path_a} vs {file_path_b}"
        else:
            errors_b = extract_errors_filtered(file_path_a, parser_a, t_b_start, t_b_end)
            comparison_desc = f"Time period comparison in {file_path_a}"

        # Calculate differences
        new_errors = {k: v for k, v in errors_b.items() if k not in errors_a}
        resolved_errors = {k: v for k, v in errors_a.items() if k not in errors_b}
        changed_errors = {
            k: {"before": errors_a[k], "after": errors_b[k]}
            for k in errors_a
            if k in errors_b and errors_a[k] != errors_b[k]
        }

        output = {
            "comparison": comparison_desc,
            "file_a": file_path_a,
            "file_b": file_path_b,
            "time_range_a": {
                "start": time_range_a_start,
                "end": time_range_a_end,
            },
            "time_range_b": {
                "start": time_range_b_start,
                "end": time_range_b_end,
            },
            "summary": {
                "errors_in_a": len(errors_a),
                "errors_in_b": len(errors_b),
                "new_errors": len(new_errors),
                "resolved_errors": len(resolved_errors),
                "changed_errors": len(changed_errors),
            },
            "new_errors": [{"pattern": k, "count": v} for k, v in list(new_errors.items())[:20]],
            "resolved_errors": [
                {"pattern": k, "count": v} for k, v in list(resolved_errors.items())[:20]
            ],
            "changed_errors": [
                {"pattern": k, "before": v["before"], "after": v["after"]}
                for k, v in list(changed_errors.items())[:20]
            ],
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Log Diff Results

**Comparison:** {comparison_desc}

### Summary
| Metric | Count |
|--------|-------|
| Errors in A | {len(errors_a)} |
| Errors in B | {len(errors_b)} |
| New Errors | {len(new_errors)} |
| Resolved Errors | {len(resolved_errors)} |
| Changed Errors | {len(changed_errors)} |

"""
        if new_errors:
            md += "### 🆕 New Errors (in B, not in A)\n"
            for pattern, count in list(new_errors.items())[:10]:
                md += f"- **{pattern[:80]}{'...' if len(pattern) > 80 else ''}** ({count}x)\n"
            md += "\n"

        if resolved_errors:
            md += "### ✅ Resolved Errors (in A, not in B)\n"
            for pattern, count in list(resolved_errors.items())[:10]:
                md += f"- **{pattern[:80]}{'...' if len(pattern) > 80 else ''}** ({count}x)\n"
            md += "\n"

        if changed_errors:
            md += "### 📊 Changed Error Counts\n"
            for pattern, change in list(changed_errors.items())[:10]:
                delta = change["after"] - change["before"]
                arrow = "↑" if delta > 0 else "↓"
                md += f"- **{pattern[:60]}{'...' if len(pattern) > 60 else ''}**: {change['before']} → {change['after']} ({arrow}{abs(delta)})\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path_a)


# =============================================================================
# Tool 8: log_analyzer_watch (P1)
# =============================================================================


@mcp.tool()
def log_analyzer_watch(
    file_path: str,
    from_position: int = 0,
    max_lines: int = 100,
    level_filter: str | None = None,
    pattern_filter: str | None = None,
    response_format: str = "markdown",
) -> str:
    """
    Watch a log file for new entries since a given position.

    This enables polling-based log watching. First call with from_position=0
    returns the current end-of-file position. Subsequent calls with the
    returned position get new entries added since then.

    Args:
        file_path: Path to the log file to watch
        from_position: File position to read from. Use 0 for initial call
                       (returns current end position), or use the returned
                       current_position from a previous call.
        max_lines: Maximum lines to read per call (1-1000, default: 100)
        level_filter: Filter by log levels, comma-separated (e.g., "ERROR,WARN")
        pattern_filter: Regex pattern to filter messages
        response_format: Output format - 'markdown' or 'json'

    Returns:
        New log entries since the last position, with updated position for
        the next call.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Get parser for this file
        parser, _ = detect_format(file_path)

        # Use the watcher
        watcher = LogWatcher()
        result = watcher.watch(
            file_path=file_path,
            parser=parser,
            from_position=from_position,
            max_lines=min(max_lines, 1000),
            level_filter=level_filter,
            pattern_filter=pattern_filter,
        )

        output = {
            "file": file_path,
            "from_position": from_position,
            "current_position": result.current_position,
            "file_size": result.file_size,
            "lines_read": result.lines_read,
            "new_entries_count": len(result.new_entries),
            "has_more": result.has_more,
            "new_entries": [
                {
                    "line_number": e.line_number,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "level": e.level.value if e.level else None,
                    "message": e.message[:500],
                    "metadata": e.metadata,
                }
                for e in result.new_entries
            ],
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        if from_position == 0:
            # Initial call - just report position
            md = f"""## Log Watch Initialized

**File:** `{file_path}`
**File Size:** {result.file_size:,} bytes
**Current Position:** {result.current_position}

Use `from_position={result.current_position}` in subsequent calls to get new entries.
"""
        else:
            md = f"""## Log Watch Results

**File:** `{file_path}`
**Position:** {from_position} → {result.current_position}
**New Entries:** {len(result.new_entries)}
"""
            if level_filter:
                md += f"**Level Filter:** {level_filter}\n"
            if pattern_filter:
                md += f"**Pattern Filter:** `{pattern_filter}`\n"

            if result.has_more:
                md += "\n⚠️ More entries available. Call again with same position to continue.\n"

            if result.new_entries:
                md += "\n### New Entries\n\n```\n"
                for entry in result.new_entries:
                    ts = entry.timestamp.isoformat()[:19] if entry.timestamp else "N/A"
                    level = entry.level.value if entry.level else "---"
                    msg = entry.message[:120]
                    md += f"[{ts}] {level:8} {msg}\n"
                md += "```\n"
            else:
                md += "\nNo new entries since last position.\n"

            md += f"\n**Next call:** `from_position={result.current_position}`"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 9: log_analyzer_suggest_patterns (P1)
# =============================================================================


@mcp.tool()
def log_analyzer_suggest_patterns(
    file_path: str,
    focus: str = "all",
    max_patterns: int = 10,
    max_lines: int = 10000,
    response_format: str = "markdown",
) -> str:
    """
    Analyze a log file and suggest useful search patterns.

    Scans the log content to identify patterns for:
    - Common error templates (normalized messages)
    - Identifiers (UUIDs, request IDs, user IDs, session IDs)
    - Security indicators (auth failures, suspicious activity)
    - Performance indicators (slow requests, high memory)
    - HTTP endpoints with errors

    Args:
        file_path: Path to the log file to analyze
        focus: Analysis focus - 'all', 'errors', 'security', 'performance',
               or 'identifiers' (default: 'all')
        max_patterns: Maximum patterns to suggest (1-20, default: 10)
        max_lines: Maximum lines to analyze (100-100000, default: 10000)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Suggested search patterns with descriptions, match counts, and examples.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Validate focus
        valid_focuses = {"all", "errors", "security", "performance", "identifiers"}
        if focus.lower() not in valid_focuses:
            return f"Error: Invalid focus '{focus}'. Valid options: {', '.join(valid_focuses)}"

        # Get parser for this file
        parser, confidence = detect_format(file_path)
        file_info = get_file_info(file_path)

        # Use the pattern suggester
        suggester = PatternSuggester()
        result = suggester.analyze_file(
            file_path=file_path,
            parser=parser,
            focus=focus.lower(),
            max_patterns=min(max_patterns, 20),
            max_lines=min(max_lines, 100000),
        )

        output = {
            "file": file_path,
            "format": {"name": parser.name, "confidence": round(confidence, 2)},
            "file_size": file_info,
            "focus": focus,
            "analysis_summary": result.analysis_summary,
            "lines_analyzed": result.lines_analyzed,
            "error_count": result.error_count,
            "warning_count": result.warning_count,
            "patterns": [p.to_dict() for p in result.patterns],
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Suggested Search Patterns

**File:** `{file_path}`
**Format:** {parser.name} (confidence: {confidence:.0%})
**Focus:** {focus}

### Summary
{result.analysis_summary}

"""
        if not result.patterns:
            md += "*No significant patterns found. Try analyzing more lines or a different focus.*\n"
        else:
            # Group by priority
            high_priority = [p for p in result.patterns if p.priority == "high"]
            medium_priority = [p for p in result.patterns if p.priority == "medium"]
            low_priority = [p for p in result.patterns if p.priority == "low"]

            if high_priority:
                md += "### 🔴 High Priority\n\n"
                for i, p in enumerate(high_priority, 1):
                    md += f"**{i}. {p.description}**\n"
                    md += f"- **Pattern:** `{p.pattern}`\n"
                    md += f"- **Category:** {p.category}\n"
                    if p.examples:
                        md += f"- **Example:** `{p.examples[0][:100]}`\n"
                    md += "\n"

            if medium_priority:
                md += "### 🟡 Medium Priority\n\n"
                for i, p in enumerate(medium_priority, 1):
                    md += f"**{i}. {p.description}**\n"
                    md += f"- **Pattern:** `{p.pattern}`\n"
                    md += f"- **Category:** {p.category}\n"
                    if p.examples:
                        md += f"- **Example:** `{p.examples[0][:100]}`\n"
                    md += "\n"

            if low_priority:
                md += "### 🟢 Low Priority\n\n"
                for i, p in enumerate(low_priority, 1):
                    md += f"**{i}. {p.description}**\n"
                    md += f"- **Pattern:** `{p.pattern}`\n"
                    md += f"- **Category:** {p.category}\n"
                    md += "\n"

        md += """
### Usage Tips
Use these patterns with `log_analyzer_search`:
```
log_analyzer_search(file_path, pattern="<pattern>", is_regex=True)
```
"""

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Server Entry Point
# =============================================================================


def main() -> None:
    """Entry point for the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
