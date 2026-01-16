"""FastMCP server for log analysis tools.

This MCP server provides 14 tools for intelligent log file analysis and debugging
assistance. All tools follow MCP best practices with proper annotations.
"""

import json
import os
import re
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from codesdevs_log_analyzer.analyzers import (
    Correlator,
    ErrorExtractor,
    LogWatcher,
    MultiFileAnalyzer,
    PatternSuggester,
    QueryTranslator,
    Summarizer,
    TraceExtractor,
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

# Initialize FastMCP server with proper naming convention (underscores for Python)
mcp = FastMCP(
    "log_analyzer_mcp",
    instructions=(
        "MCP server for intelligent log file analysis and debugging assistance. "
        "Provides tools to parse, search, analyze, and debug log files across "
        "multiple formats including syslog, Apache, Nginx, Docker, Kubernetes, "
        "Python, Java, and JSON Lines."
    ),
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Parse Log File",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Search Log Patterns",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Extract Errors from Log",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Summarize Log File",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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
            "security": summary.security.to_dict() if summary.security else None,
            "performance": summary.performance.to_dict() if summary.performance else None,
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

        # Security indicators section
        if summary.security:
            sec = summary.security
            has_security_concerns = (
                sec.failed_auth_attempts > 0
                or sec.brute_force_indicators
                or sec.sql_injection_attempts > 0
                or sec.path_traversal_attempts > 0
                or sec.xss_attempts > 0
                or sec.suspicious_user_agents
                or sec.privilege_escalation_indicators > 0
            )
            if has_security_concerns:
                md += "\n### Security Analysis\n"
                if sec.security_summary:
                    md += f"**Summary:** {sec.security_summary}\n\n"

                if sec.failed_auth_attempts > 0:
                    md += f"- 🔐 **Authentication failures:** {sec.failed_auth_attempts}\n"
                if sec.brute_force_indicators:
                    md += f"- 🚨 **Potential brute force sources:** {len(sec.brute_force_indicators)}\n"
                    for bf in sec.brute_force_indicators[:3]:
                        md += f"  - IP `{bf['ip']}`: {bf['attempts']} failed attempts\n"
                if sec.sql_injection_attempts > 0:
                    md += f"- 💉 **SQL injection attempts:** {sec.sql_injection_attempts}\n"
                if sec.path_traversal_attempts > 0:
                    md += f"- 📁 **Path traversal attempts:** {sec.path_traversal_attempts}\n"
                if sec.xss_attempts > 0:
                    md += f"- ⚡ **XSS attempts:** {sec.xss_attempts}\n"
                if sec.privilege_escalation_indicators > 0:
                    md += f"- 👑 **Privilege escalation indicators:** {sec.privilege_escalation_indicators}\n"
                if sec.suspicious_user_agents:
                    md += f"- 🤖 **Suspicious user agents:** {len(sec.suspicious_user_agents)}\n"
                    for ua in sec.suspicious_user_agents[:3]:
                        md += f"  - `{ua[:60]}{'...' if len(ua) > 60 else ''}`\n"

                if sec.error_4xx_count > 0 or sec.error_5xx_count > 0:
                    md += f"\n**HTTP Errors:** {sec.error_4xx_count} client (4xx), {sec.error_5xx_count} server (5xx)\n"

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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Tail Log File",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Correlate Log Events",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Compare Log Files",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Watch Log File",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,  # Returns different results based on file changes
        openWorldHint=False,
    ),
)
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


@mcp.tool(
    annotations=ToolAnnotations(
        title="Suggest Search Patterns",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
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
# Tool 10: log_analyzer_trace (P0 - Phase 1)
# =============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Extract Trace IDs",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def log_analyzer_trace(
    file_path: str,
    trace_id: str | None = None,
    max_traces: int = 100,
    max_lines: int = 10000,
    response_format: str = "markdown",
) -> str:
    """
    Extract and follow trace/correlation IDs across log entries.

    Automatically detects trace IDs (OpenTelemetry, X-Request-ID, AWS X-Ray, UUID)
    and groups related log entries to show request flows through your system.

    Args:
        file_path: Path to the log file to analyze
        trace_id: Specific trace ID to filter for (None for all traces)
        max_traces: Maximum number of trace groups to return (1-500, default: 100)
        max_lines: Maximum lines to process (100-100000, default: 10000)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Trace groups showing request flows, including trace ID types detected,
        entry counts, time spans, and error indicators.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        file_info = get_file_info(file_path)
        parser, confidence = detect_format(file_path)

        # Use trace extractor
        extractor = TraceExtractor(
            trace_id=trace_id,
            max_traces=min(max_traces, 500),
        )

        result = extractor.analyze_file(
            parser=parser,
            file_path=file_path,
            max_lines=min(max_lines, 100000),
        )

        output = {
            "file": file_path,
            "format": {"name": parser.name, "confidence": round(confidence, 2)},
            "file_size": file_info,
            "filter_trace_id": trace_id,
            "total_entries": result.total_entries,
            "entries_with_traces": result.entries_with_traces,
            "trace_coverage": round(
                result.entries_with_traces / result.total_entries * 100, 1
            )
            if result.total_entries > 0
            else 0,
            "unique_trace_ids": result.unique_trace_ids,
            "detected_formats": result.detected_trace_formats,
            "error_trace_count": len(result.error_traces),
            "trace_groups": [g.to_dict() for g in result.trace_groups[:50]],
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Trace ID Analysis

**File:** `{file_path}`
**Format:** {parser.name} (confidence: {confidence:.0%})
**Size:** {file_info["size_human"]}

### Overview
- **Total Entries:** {result.total_entries:,}
- **Entries with Traces:** {result.entries_with_traces:,} ({output["trace_coverage"]}%)
- **Unique Trace IDs:** {result.unique_trace_ids}
- **Traces with Errors:** {len(result.error_traces)}

### Detected Trace ID Formats
"""
        if result.detected_trace_formats:
            for fmt, count in sorted(
                result.detected_trace_formats.items(), key=lambda x: -x[1]
            ):
                md += f"- **{fmt}:** {count:,} entries\n"
        else:
            md += "*No trace IDs detected*\n"

        if result.trace_groups:
            md += "\n### Trace Groups\n\n"
            for i, group in enumerate(result.trace_groups[:20], 1):
                error_indicator = "🔴" if group.has_errors else "🟢"
                md += f"#### {i}. {error_indicator} `{group.trace_id[:32]}{'...' if len(group.trace_id) > 32 else ''}`\n"
                md += f"- **Type:** {group.trace_id_type}\n"
                md += f"- **Entries:** {group.entry_count}\n"
                if group.duration_ms is not None:
                    md += f"- **Duration:** {group.duration_ms:.2f}ms\n"
                if group.start_time:
                    md += f"- **Start:** {group.start_time.isoformat()}\n"
                if group.sources:
                    md += f"- **Sources:** {', '.join(list(group.sources)[:5])}\n"
                if group.has_errors:
                    md += f"- **Errors:** {group.error_count}\n"
                md += "\n"

        if not result.trace_groups and trace_id:
            md += f"\n*No entries found for trace ID: `{trace_id}`*\n"

        md += """
### Usage Tips
- Use `trace_id` parameter to follow a specific request
- Traces with errors (🔴) may indicate failed requests
- Duration helps identify slow requests
"""

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 11: log_analyzer_multi (P0 - Phase 1)
# =============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Multi-File Analysis",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def log_analyzer_multi(
    file_paths: list[str],
    operation: str = "merge",
    time_window: int = 60,
    max_entries: int = 1000,
    response_format: str = "markdown",
) -> str:
    """
    Analyze multiple log files together for cross-file debugging.

    Supports three operations:
    - merge: Interleave entries by timestamp (like 'sort -m')
    - correlate: Find events happening across files within time window
    - compare: Diff error patterns between files

    Args:
        file_paths: List of log file paths to analyze (2-10 files)
        operation: Analysis operation - 'merge', 'correlate', or 'compare' (default: 'merge')
        time_window: Time window in seconds for correlation (1-3600, default: 60)
        max_entries: Maximum entries to return (100-5000, default: 1000)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Combined analysis results based on the selected operation.
    """
    try:
        # Validate file paths
        if not file_paths or len(file_paths) < 2:
            return "Error: At least 2 file paths are required for multi-file analysis."

        if len(file_paths) > 10:
            return "Error: Maximum 10 files supported for multi-file analysis."

        # Check all files exist
        for fp in file_paths:
            if not os.path.isfile(fp):
                return handle_tool_error(FileNotFoundError(), fp)

        # Validate operation
        valid_ops = {"merge", "correlate", "compare"}
        if operation.lower() not in valid_ops:
            return f"Error: Invalid operation '{operation}'. Valid options: {', '.join(valid_ops)}"

        # Use multi-file analyzer
        analyzer = MultiFileAnalyzer(
            time_window=min(max(time_window, 1), 3600),
            max_entries=min(max(max_entries, 100), 5000),
        )

        op = operation.lower()
        if op == "merge":
            result = analyzer.merge_files(file_paths)
        elif op == "correlate":
            result = analyzer.correlate_files(file_paths)
        else:  # compare
            result = analyzer.compare_files(file_paths)

        # Build output
        output = {
            "operation": op,
            "files": file_paths,
            "file_count": len(file_paths),
            "time_window_seconds": time_window if op == "correlate" else None,
            "total_entries": result.total_entries,
            "files_info": result.files_info,
        }

        if op == "merge":
            output["merged_entries"] = [
                {
                    "source_file": e.source_file,
                    "line_number": e.line_number,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "level": e.level,
                    "message": e.message[:300],
                }
                for e in result.merged_entries[:max_entries]
            ]
            output["time_range"] = {
                "start": result.time_range[0].isoformat() if result.time_range[0] else None,
                "end": result.time_range[1].isoformat() if result.time_range[1] else None,
            }
        elif op == "correlate":
            output["clusters"] = [
                {
                    "cluster_id": c.cluster_id,
                    "start_time": c.start_time.isoformat() if c.start_time else None,
                    "end_time": c.end_time.isoformat() if c.end_time else None,
                    "files_involved": list(c.files_involved),
                    "entry_count": c.entry_count,
                    "has_errors": c.has_errors,
                    "entries": [
                        {
                            "source_file": e.source_file,
                            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                            "level": e.level,
                            "message": e.message[:200],
                        }
                        for e in c.entries[:10]
                    ],
                }
                for c in result.correlation_clusters[:50]
            ]
            output["cluster_count"] = len(result.correlation_clusters)
        else:  # compare
            output["comparison"] = {
                "common_errors": [
                    {"pattern": p, "counts": c}
                    for p, c in list(result.comparison.get("common_errors", {}).items())[:20]
                ],
                "unique_errors": {
                    fp: list(errors)[:10]
                    for fp, errors in result.comparison.get("unique_errors", {}).items()
                },
                "level_distribution": result.comparison.get("level_distribution", {}),
            }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Multi-File Analysis

**Operation:** {op.title()}
**Files:** {len(file_paths)}

### Files Analyzed
"""
        for fp in file_paths:
            info = result.files_info.get(fp, {})
            md += f"- `{fp}` ({info.get('format', 'unknown')}, {info.get('entries', 0):,} entries)\n"

        if op == "merge":
            md += f"""
### Merged Timeline
**Total Entries:** {result.total_entries:,}
"""
            if result.time_range[0] and result.time_range[1]:
                md += f"**Time Range:** {result.time_range[0].isoformat()} to {result.time_range[1].isoformat()}\n"

            md += "\n#### Recent Entries\n```\n"
            for entry in result.merged_entries[:30]:
                ts = entry.timestamp.isoformat()[:19] if entry.timestamp else "N/A"
                level = entry.level or "---"
                src = os.path.basename(entry.source_file)[:15]
                msg = entry.message[:80]
                md += f"[{ts}] {level:8} [{src}] {msg}\n"
            md += "```\n"

        elif op == "correlate":
            md += f"""
### Correlation Results
**Time Window:** ±{time_window} seconds
**Clusters Found:** {len(result.correlation_clusters)}

"""
            for i, cluster in enumerate(result.correlation_clusters[:10], 1):
                error_indicator = "🔴" if cluster.has_errors else "🟢"
                md += f"#### Cluster {i} {error_indicator}\n"
                md += f"- **Files:** {', '.join(os.path.basename(f) for f in cluster.files_involved)}\n"
                md += f"- **Entries:** {cluster.entry_count}\n"
                if cluster.start_time:
                    md += f"- **Time:** {cluster.start_time.isoformat()}\n"
                md += "\n"

        else:  # compare
            md += "\n### Comparison Results\n"

            common = result.comparison.get("common_errors", {})
            if common:
                md += "\n#### Common Errors (across all files)\n"
                for pattern, counts in list(common.items())[:10]:
                    md += f"- `{pattern[:60]}{'...' if len(pattern) > 60 else ''}`\n"
                    for fp, cnt in counts.items():
                        md += f"  - {os.path.basename(fp)}: {cnt}x\n"

            unique = result.comparison.get("unique_errors", {})
            if unique:
                md += "\n#### Unique Errors (per file)\n"
                for fp, errors in unique.items():
                    if errors:
                        md += f"\n**{os.path.basename(fp)}:**\n"
                        for err in list(errors)[:5]:
                            md += f"- `{err[:60]}{'...' if len(err) > 60 else ''}`\n"

            level_dist = result.comparison.get("level_distribution", {})
            if level_dist:
                md += "\n#### Level Distribution by File\n"
                md += "| File | ERROR | WARN | INFO |\n"
                md += "|------|-------|------|------|\n"
                for fp, levels in level_dist.items():
                    md += f"| {os.path.basename(fp)[:20]} | {levels.get('ERROR', 0)} | {levels.get('WARN', 0)} | {levels.get('INFO', 0)} |\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_paths[0] if file_paths else "unknown")


@mcp.tool(
    annotations=ToolAnnotations(
        title="Ask About Logs",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def log_analyzer_ask(
    file_path: str,
    question: str,
    max_results: int = 50,
    response_format: str = "markdown",
) -> str:
    """
    Answer questions about log files using AI-assisted analysis.

    Translates natural language questions into appropriate log analysis
    operations and provides intelligent, contextual answers.

    Example questions:
    - "Why did the database connection fail?"
    - "How many errors occurred in the last hour?"
    - "What happened before the server crashed?"
    - "Show me all authentication failures"
    - "When did the first timeout occur?"

    Args:
        file_path: Path to the log file to analyze
        question: Natural language question about the logs
        max_results: Maximum supporting entries to include (10-200, default: 50)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Natural language answer with supporting log entries and suggestions.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Detect format and get parser
        parser, _confidence = detect_format(file_path)

        # Initialize query translator
        translator = QueryTranslator()

        # Translate the question to an intent
        intent = translator.translate(question)

        # Get suggested tool calls
        tool_calls = translator.generate_tool_calls(intent)

        # Build search pattern from intent
        search_pattern = translator.build_search_pattern(intent)

        # Collect results
        results: dict[str, Any] = {}
        entries: list[ParsedLogEntry] = []

        # Execute appropriate analysis based on intent
        if intent.primary_action == "find_cause":
            # Extract errors first
            extractor = ErrorExtractor(
                include_warnings=False,
                group_similar=True,
                max_errors=min(max(max_results, 10), 200),
            )
            error_result = extractor.analyze_file(parser, file_path)

            # Collect sample entries from error groups
            for group in error_result.error_groups:
                for entry in group.sample_entries:
                    if len(entries) < max_results:
                        entries.append(entry)

            # Then correlate for root cause if we have errors
            if error_result.error_groups:
                # Use the first error template as anchor
                first_group = error_result.error_groups[0]
                error_pattern = first_group.template[:50] if first_group.template else "error"
                correlator = Correlator(
                    anchor_pattern=re.escape(error_pattern),
                    window_before=60,
                    window_after=30,
                    detect_causal_chain=True,
                    include_recommendations=True,
                )
                corr_result = correlator.correlate_file(parser, file_path)
                results["causal_chain"] = {
                    "detected": corr_result.causal_chain_detected,
                    "hypothesis": corr_result.root_cause_summary,
                }
                results["recommendations"] = corr_result.recommendations

        elif intent.primary_action == "analyze":
            # Summarize the log file
            summarizer = Summarizer(
                file_path=file_path,
            )
            summary = summarizer.summarize_file(parser, max_lines=10000)

            # Build summary text
            level_dist = summary.level_distribution
            error_count = level_dist.get("ERROR", 0) + level_dist.get("CRITICAL", 0)
            warning_count = level_dist.get("WARNING", 0) + level_dist.get("WARN", 0)

            results["summary"] = f"""### Log Summary
**Total Entries:** {summary.total_entries:,}
**Errors:** {error_count}
**Warnings:** {warning_count}
"""
            if summary.top_errors:
                results["summary"] += "\n#### Top Errors\n"
                for error_group in summary.top_errors[:5]:
                    results["summary"] += f"- ({error_group.count}x) {error_group.template[:80]}\n"

            # Get sample entries matching the focus
            for parsed_entry in parser.parse_file(file_path, max_lines=max_results * 2):
                if intent.focus == "errors":
                    if parsed_entry.level and parsed_entry.level.upper() in ("ERROR", "CRITICAL"):
                        entries.append(parsed_entry)
                else:
                    entries.append(parsed_entry)
                if len(entries) >= max_results:
                    break

        elif intent.primary_action == "count":
            # Count matching entries
            count = 0
            pattern_re = None
            if search_pattern:
                try:
                    pattern_re = re.compile(search_pattern, re.IGNORECASE)
                except re.error:
                    pattern_re = None

            for parsed_entry in parser.parse_file(file_path):
                matches = False
                if pattern_re and parsed_entry.message:
                    matches = bool(pattern_re.search(parsed_entry.message))
                elif intent.focus == "errors" and parsed_entry.level:
                    matches = parsed_entry.level.upper() in ("ERROR", "CRITICAL")
                elif intent.focus == "warnings" and parsed_entry.level:
                    matches = parsed_entry.level.upper() in ("WARNING", "WARN")
                elif not intent.focus and not pattern_re:
                    matches = True

                if matches:
                    count += 1
                    if len(entries) < max_results:
                        entries.append(parsed_entry)

            results["count"] = count

        elif intent.primary_action == "time_range":
            # Time-based search
            found_entries: list[ParsedLogEntry] = []
            pattern_re = None
            if search_pattern:
                try:
                    pattern_re = re.compile(search_pattern, re.IGNORECASE)
                except re.error:
                    pattern_re = None

            for parsed_entry in parser.parse_file(file_path):
                matches = False
                if pattern_re and parsed_entry.message:
                    matches = bool(pattern_re.search(parsed_entry.message))
                elif intent.focus == "errors" and parsed_entry.level:
                    matches = parsed_entry.level.upper() in ("ERROR", "CRITICAL")
                elif not pattern_re and not intent.focus:
                    matches = True

                if matches:
                    found_entries.append(parsed_entry)

            # Sort by timestamp if available
            timed = [e for e in found_entries if e.timestamp]
            if timed:
                timed.sort(key=lambda x: x.timestamp or datetime.min)
                if intent.aggregation == "first":
                    entries = timed[:max_results]
                elif intent.aggregation == "last":
                    entries = timed[-max_results:]
                else:
                    entries = timed[:max_results]
            else:
                entries = found_entries[:max_results]

        else:  # Default: search
            pattern_re = None
            if search_pattern:
                try:
                    pattern_re = re.compile(search_pattern, re.IGNORECASE)
                except re.error:
                    pattern_re = None

            for parsed_entry in parser.parse_file(file_path):
                matches = False
                if pattern_re and parsed_entry.message:
                    matches = bool(pattern_re.search(parsed_entry.message))
                elif intent.focus == "errors" and parsed_entry.level:
                    matches = parsed_entry.level.upper() in ("ERROR", "CRITICAL")
                elif not search_pattern and not intent.focus:
                    if len(entries) < max_results:
                        entries.append(parsed_entry)
                    continue

                if matches and len(entries) < max_results:
                    entries.append(parsed_entry)

        # Format the answer
        answer = translator.format_answer(intent, results, entries)

        # Get follow-up suggestions
        suggestions = translator.suggest_followup(intent)

        # Build output
        output: dict[str, Any] = {
            "question": question,
            "intent": {
                "action": intent.primary_action,
                "focus": intent.focus,
                "confidence": intent.confidence,
                "pattern": intent.pattern,
            },
            "answer": answer,
            "supporting_entries_count": len(entries),
            "tool_calls": tool_calls,
            "suggestions": suggestions,
        }

        if entries:
            output["supporting_entries"] = [
                {
                    "line_number": e.line_number,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "level": e.level,
                    "message": e.message[:200] if e.message else None,
                }
                for e in entries[:20]  # Limit to 20 for output
            ]

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        md = f"""## Log Analysis Answer

**Question:** {question}

### Answer
{answer}

### Analysis Details
- **Intent:** {intent.primary_action}
- **Focus:** {intent.focus or "general"}
- **Confidence:** {intent.confidence:.0%}
- **Supporting entries:** {len(entries)}
"""

        if entries:
            md += "\n### Sample Entries\n```\n"
            for entry in entries[:10]:
                ts = entry.timestamp.isoformat()[:19] if entry.timestamp else "N/A"
                level = entry.level or "---"
                msg = (entry.message or "")[:80]
                md += f"[{ts}] {level:8} {msg}\n"
            md += "```\n"

        if suggestions:
            md += "\n### Suggested Follow-up Questions\n"
            for s in suggestions:
                md += f"- {s}\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 13: log_analyzer_scan_sensitive (P2)
# =============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Scan Sensitive Data",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def log_analyzer_scan_sensitive(
    file_path: str,
    redact: bool = False,
    categories: list[str] | None = None,
    include_ips: bool = False,
    max_matches: int = 100,
    max_lines: int = 100000,
    response_format: str = "markdown",
) -> str:
    """
    Detect sensitive data in logs (PII, credentials, API keys).

    Scans log files for potentially sensitive information including:
    - Email addresses
    - Credit card numbers (Visa, MasterCard, Amex)
    - API keys and tokens (AWS, GitHub, Slack, generic)
    - Passwords in URLs or config
    - Social Security Numbers (SSN)
    - JWT and Bearer tokens
    - Database connection strings
    - Private key markers
    - Phone numbers
    - IP addresses (optional)

    Args:
        file_path: Path to the log file to scan
        redact: Redact sensitive data in output (default: False)
        categories: Filter to specific categories. Options:
                   email, credit_card, api_key, token, password,
                   ssn, ip_address, phone, connection_string, private_key
        include_ips: Include IP address detection (default: False)
        max_matches: Maximum matches to return (1-500, default: 100)
        max_lines: Maximum lines to scan (1-1000000, default: 100000)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Sensitive data scan results with matches and statistics.
    """
    try:
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Get parser
        parser, _ = detect_format(file_path)

        # Create detector
        from codesdevs_log_analyzer.analyzers import SensitiveDataDetector

        detector = SensitiveDataDetector(include_private_ips=include_ips)

        # Scan file
        result = detector.analyze_file(
            file_path=file_path,
            parser=parser,
            redact=redact,
            max_matches=min(max(max_matches, 1), 500),
            max_lines=min(max(max_lines, 1), 1000000),
            categories=categories,
        )

        # Build output
        output: dict[str, Any] = {
            "file": file_path,
            "lines_scanned": result.lines_scanned,
            "total_matches": result.total_matches,
            "matches_by_category": result.matches_by_category,
            "matches_by_severity": result.matches_by_severity,
            "summary": result.summary,
            "matches": [m.to_dict() for m in result.matches],
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        severity_emoji = {
            "high": "🔴",
            "medium": "🟡",
            "low": "🟢",
        }

        md = f"""## Sensitive Data Scan Results

**File:** `{file_path}`
**Lines Scanned:** {result.lines_scanned:,}
**Total Matches:** {result.total_matches}

### Summary
{result.summary}

"""
        if result.matches_by_severity:
            md += "### Severity Breakdown\n"
            for sev in ["high", "medium", "low"]:
                count = result.matches_by_severity.get(sev, 0)
                if count > 0:
                    md += f"- {severity_emoji.get(sev, '')} **{sev.upper()}**: {count}\n"
            md += "\n"

        if result.matches_by_category:
            md += "### Category Breakdown\n"
            for cat, count in sorted(
                result.matches_by_category.items(), key=lambda x: x[1], reverse=True
            ):
                md += f"- **{cat}**: {count}\n"
            md += "\n"

        if result.matches:
            md += f"### Matches ({len(result.matches)} shown)\n"
            for match in result.matches[:50]:  # Limit display
                emoji = severity_emoji.get(match.severity, "")
                md += f"\n#### {emoji} Line {match.line_number} - {match.category}\n"
                md += f"**Pattern:** {match.pattern_name}\n"
                if redact:
                    md += f"**Redacted:** `{match.redacted_text}`\n"
                else:
                    md += f"**Matched:** `{match.matched_text}`\n"
                md += f"```\n{match.context}\n```\n"

        if result.total_matches > 0:
            md += "\n### Recommendations\n"
            high_count = result.matches_by_severity.get("high", 0)
            if high_count > 0:
                md += f"- ⚠️ **{high_count} HIGH severity matches** require immediate attention\n"
                md += "- Review and remove credentials, API keys, and sensitive PII from logs\n"
                md += "- Consider implementing log sanitization in your application\n"
            if result.matches_by_category.get("password", 0) > 0:
                md += "- **Never log passwords** - implement proper secret management\n"
            if result.matches_by_category.get("credit_card", 0) > 0:
                md += "- **PCI-DSS violation** - credit card numbers must never be logged\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


# =============================================================================
# Tool 14: log_analyzer_suggest_format (P2)
# =============================================================================


@mcp.tool(
    annotations=ToolAnnotations(
        title="Suggest Log Format",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def log_analyzer_suggest_format(
    file_path: str,
    sample_size: int = 100,
    response_format: str = "markdown",
) -> str:
    """
    Analyze a log file and suggest the best parsing approach.

    Returns detailed format detection information including:
    - Detected format with confidence score
    - Alternative formats to try if confidence is low
    - Sample of unparseable lines with suggestions
    - Custom pattern suggestions for generic parser

    Args:
        file_path: Path to the log file to analyze
        sample_size: Number of lines to sample for analysis (default: 100)
        response_format: Output format - 'markdown' or 'json'

    Returns:
        Format suggestions and analysis results
    """
    try:
        # Validate file exists
        if not os.path.isfile(file_path):
            return handle_tool_error(FileNotFoundError(), file_path)

        # Read sample lines
        sample_lines: list[str] = []
        for _, line in stream_file(file_path, max_lines=sample_size):
            sample_lines.append(line)

        if not sample_lines:
            return json.dumps({"error": "Empty file"}) if response_format.lower() == "json" else "**Error:** File is empty"

        # Test all parsers and collect confidence scores
        parser_scores: list[tuple[str, float, int, int]] = []  # (name, confidence, parsed_count, failed_count)

        for parser_name in PARSER_REGISTRY:
            parser_class = PARSER_REGISTRY[parser_name]
            confidence = parser_class.detect_confidence(sample_lines)

            # Count parsed vs failed lines
            parser = parser_class()
            parsed_count = 0
            failed_count = 0

            for i, line in enumerate(sample_lines[:50], 1):  # Test first 50 lines
                entry = parser.parse_line(line, i)
                if entry and entry.message:
                    parsed_count += 1
                else:
                    failed_count += 1

            parser_scores.append((parser_name, confidence, parsed_count, failed_count))

        # Sort by confidence
        parser_scores.sort(key=lambda x: x[1], reverse=True)

        # Get best parser
        best_parser_name = parser_scores[0][0]
        best_confidence = parser_scores[0][1]
        best_parser = PARSER_REGISTRY[best_parser_name]()

        # Find unparseable lines with the best parser
        unparseable_lines: list[tuple[int, str]] = []
        for i, line in enumerate(sample_lines, 1):
            entry = best_parser.parse_line(line, i)
            if entry is None or not entry.message:
                unparseable_lines.append((i, line[:200]))
                if len(unparseable_lines) >= 5:
                    break

        # Generate pattern suggestions for generic parser
        pattern_suggestions: list[str] = []
        if best_confidence < 0.7:
            # Analyze common patterns in the file
            patterns_found = _analyze_line_patterns(sample_lines[:20])
            pattern_suggestions = patterns_found

        # Get format descriptions
        format_info: list[dict[str, Any]] = []
        for name, conf, parsed, failed in parser_scores[:5]:  # Top 5
            parser_class = PARSER_REGISTRY[name]
            format_info.append({
                "name": name,
                "description": parser_class.description,
                "confidence": conf,
                "parsed_lines": parsed,
                "failed_lines": failed,
            })

        # Build output
        output: dict[str, Any] = {
            "recommended_format": best_parser_name,
            "confidence": best_confidence,
            "confidence_level": "high" if best_confidence >= 0.8 else "medium" if best_confidence >= 0.5 else "low",
            "total_lines_sampled": len(sample_lines),
            "format_rankings": format_info,
            "unparseable_sample": [
                {"line_number": num, "content": line}
                for num, line in unparseable_lines
            ],
            "pattern_suggestions": pattern_suggestions,
            "recommendations": _generate_format_recommendations(
                best_parser_name, best_confidence, unparseable_lines, parser_scores
            ),
        }

        if response_format.lower() == "json":
            return json.dumps(output, indent=2)

        # Markdown format
        confidence_emoji = "✅" if best_confidence >= 0.8 else "⚠️" if best_confidence >= 0.5 else "❌"

        md = f"""## Log Format Analysis

### Recommended Format
{confidence_emoji} **{best_parser_name}** (confidence: {best_confidence:.0%})

{PARSER_REGISTRY[best_parser_name].description}

### Format Rankings
| Format | Confidence | Parsed | Failed |
|--------|-----------|--------|--------|
"""
        for info in format_info:
            md += f"| {info['name']} | {info['confidence']:.0%} | {info['parsed_lines']} | {info['failed_lines']} |\n"

        if unparseable_lines:
            md += f"\n### Unparseable Lines ({len(unparseable_lines)} samples)\n"
            md += "These lines couldn't be parsed with the recommended format:\n```\n"
            for num, line in unparseable_lines:
                md += f"L{num}: {line}\n"
            md += "```\n"

        if pattern_suggestions:
            md += "\n### Pattern Suggestions\n"
            md += "If using the generic parser, consider these patterns:\n"
            for suggestion in pattern_suggestions:
                md += f"- `{suggestion}`\n"

        recommendations = output["recommendations"]
        if recommendations:
            md += "\n### Recommendations\n"
            for rec in recommendations:
                md += f"- {rec}\n"

        return md

    except Exception as e:
        return handle_tool_error(e, file_path)


def _analyze_line_patterns(sample_lines: list[str]) -> list[str]:
    """Analyze sample lines to suggest timestamp/level patterns."""
    suggestions: list[str] = []

    # Common timestamp patterns to look for
    timestamp_patterns = [
        (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', "ISO format timestamp"),
        (r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', "Apache/Nginx timestamp"),
        (r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', "Syslog timestamp"),
        (r'\d{2}:\d{2}:\d{2},\d{3}', "Log4j timestamp (HH:MM:SS,ms)"),
        (r'\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]', "Bracketed ISO timestamp"),
    ]

    # Common level patterns
    level_patterns = [
        (r'\b(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL)\b', "Standard log levels"),
        (r'\b(debug|info|warn|error|fatal)\b', "Lowercase log levels"),
        (r'\[(DEBUG|INFO|WARN|ERROR)\]', "Bracketed log levels"),
    ]

    # Check for patterns in sample
    import re
    for line in sample_lines[:10]:
        for pattern, desc in timestamp_patterns:
            if re.search(pattern, line) and desc not in [s.split(":")[0] for s in suggestions]:
                suggestions.append(f"{desc}: {pattern}")
                break

        for pattern, desc in level_patterns:
            if re.search(pattern, line, re.IGNORECASE) and desc not in [s.split(":")[0] for s in suggestions]:
                suggestions.append(f"{desc}: {pattern}")
                break

    return suggestions[:5]


def _generate_format_recommendations(
    best_format: str,
    confidence: float,
    unparseable: list[tuple[int, str]],
    all_scores: list[tuple[str, float, int, int]],
) -> list[str]:
    """Generate actionable recommendations based on analysis."""
    recommendations: list[str] = []

    if confidence >= 0.9:
        recommendations.append(f"High confidence detection. Use `--format-hint {best_format}` for best results.")
    elif confidence >= 0.7:
        recommendations.append(f"Good detection. Consider using `--format-hint {best_format}` to skip auto-detection.")
        if len(all_scores) > 1 and all_scores[1][1] >= 0.5:
            alt = all_scores[1][0]
            recommendations.append(f"Alternative: Try `--format-hint {alt}` if results are poor.")
    elif confidence >= 0.5:
        recommendations.append("Medium confidence - results may be inconsistent.")
        recommendations.append("Try multiple formats and compare results.")
        if unparseable:
            recommendations.append("Consider preprocessing the file to standardize format.")
    else:
        recommendations.append("Low confidence - file may have mixed or custom format.")
        recommendations.append("Use `--format-hint generic` for timestamp-only parsing.")
        recommendations.append("Consider checking if the file has multiple log formats mixed together.")

    if unparseable and len(unparseable) > 3:
        recommendations.append(f"Note: {len(unparseable)}+ lines couldn't be parsed - check for headers or mixed content.")

    return recommendations


# =============================================================================
# Server Entry Point
# =============================================================================


def main() -> None:
    """Entry point for the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
