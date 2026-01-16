"""Demo runner for log-analyzer-mcp.

Showcases the log analysis capabilities with beautiful terminal output.
Used for generating demo GIFs and interactive demonstrations.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    pass

# Initialize rich console
console = Console()

# Test logs directory locations (checked in order)
TEST_LOG_PATHS = [
    Path(__file__).parent.parent / "test_logs",
    Path.cwd() / "test_logs",
]


def get_test_log_path(name: str) -> Path:
    """Get path to bundled test log file."""
    for base_path in TEST_LOG_PATHS:
        path = base_path / name
        if path.exists():
            return path
    raise FileNotFoundError(f"Test log not found: {name}")


def print_banner() -> None:
    """Print the demo banner."""
    banner = Text()
    banner.append("🔍 ", style="bold")
    banner.append("Log Analyzer MCP\n", style="bold cyan")
    banner.append("AI-powered log analysis for Claude Code\n\n", style="dim")
    banner.append("14", style="bold yellow")
    banner.append(" tools  •  ", style="dim")
    banner.append("9+", style="bold yellow")
    banner.append(" formats  •  ", style="dim")
    banner.append("280", style="bold yellow")
    banner.append(" tests", style="dim")

    console.print(Panel(banner, border_style="cyan", padding=(1, 2)))
    time.sleep(1.5)


def demo_parse() -> None:
    """Demonstrate log parsing and format detection."""
    from codesdevs_log_analyzer.parsers import detect_format

    console.print("\n[bold green]━━━ Demo 1: Auto-Detect Log Format ━━━[/bold green]\n")
    console.print("[dim]$ log_analyzer_parse python_app.log[/dim]\n")
    time.sleep(0.5)

    log_path = get_test_log_path("python_app.log")
    parser, confidence = detect_format(str(log_path))

    # Count entries by level
    level_counts: dict[str, int] = {}
    total = 0
    for entry in parser.parse_file(str(log_path), max_lines=1000):
        total += 1
        level = entry.level.upper() if entry.level else "UNKNOWN"
        level_counts[level] = level_counts.get(level, 0) + 1

    # Display results
    result = Table(show_header=False, box=None, padding=(0, 1))
    result.add_column(style="cyan")
    result.add_column()

    result.add_row("Format:", f"[bold]{parser.description}[/bold] ({confidence * 100:.0f}% confidence)")
    result.add_row("File:", str(log_path.name))
    result.add_row("Entries:", f"{total:,}")

    # Level distribution
    levels_str = "  ".join(
        f"[{'red' if 'ERROR' in k else 'yellow' if 'WARN' in k else 'green'}]{k}[/]: {v}"
        for k, v in sorted(level_counts.items(), key=lambda x: -x[1])
    )
    result.add_row("Levels:", levels_str)

    console.print(result)
    console.print("\n[green]✓[/green] Format auto-detected in <100ms")
    time.sleep(2)


def demo_search() -> None:
    """Demonstrate pattern search with context."""
    from codesdevs_log_analyzer.analyzers import PatternMatcher
    from codesdevs_log_analyzer.parsers import detect_format

    console.print("\n[bold green]━━━ Demo 2: Search with Context ━━━[/bold green]\n")
    console.print('[dim]$ log_analyzer_search python_app.log "ERROR" --context 2[/dim]\n')
    time.sleep(0.5)

    log_path = get_test_log_path("python_app.log")
    parser, _ = detect_format(str(log_path))

    matcher = PatternMatcher(
        pattern="ERROR",
        regex=False,
        case_sensitive=False,
        context_before=2,
        context_after=2,
        max_matches=3,
    )

    result = matcher.search_file(parser, str(log_path), max_lines=1000)

    console.print(f"[cyan]Found {result.total_matches} matches[/cyan]\n")

    for i, match in enumerate(result.matches[:2], 1):
        console.print(f"[dim]Match {i} (line {match.line_number}):[/dim]")

        # Show context before
        for ctx_line in match.context_before[-2:]:
            console.print(f"  [dim]{ctx_line[:80]}[/dim]")

        # Show the match (highlighted)
        console.print(f"  [bold red]→ {match.entry.raw_line[:80]}[/bold red]")

        # Show context after
        for ctx_line in match.context_after[:2]:
            console.print(f"  [dim]{ctx_line[:80]}[/dim]")

        console.print()

    console.print("[green]✓[/green] Context helps understand the error cause")
    time.sleep(2)


def demo_errors() -> None:
    """Demonstrate error extraction and grouping."""
    from codesdevs_log_analyzer.analyzers.error_extractor import extract_errors
    from codesdevs_log_analyzer.parsers import detect_format

    console.print("\n[bold green]━━━ Demo 3: Extract & Group Errors ━━━[/bold green]\n")
    console.print("[dim]$ log_analyzer_extract_errors java_app.log --group[/dim]\n")
    time.sleep(0.5)

    log_path = get_test_log_path("java_app.log")
    parser, _ = detect_format(str(log_path))

    result = extract_errors(
        parser=parser,
        file_path=str(log_path),
        include_warnings=False,
        group_similar=True,
        max_lines=1000,
    )

    # Summary stats
    console.print(f"[cyan]Found {result.total_errors} errors in {result.unique_errors} groups[/cyan]\n")

    # Show top error groups
    table = Table(title="Top Error Groups", show_lines=True)
    table.add_column("Count", style="bold red", justify="right")
    table.add_column("Error Pattern", style="white")
    table.add_column("Stack Trace", style="dim")

    for group in result.error_groups[:3]:
        has_trace = "✓" if group.stack_trace else "-"
        # Truncate long templates
        template = group.template[:60] + "..." if len(group.template) > 60 else group.template
        table.add_row(str(group.count), template, has_trace)

    console.print(table)
    console.print("\n[green]✓[/green] Similar errors grouped to reduce noise")
    time.sleep(2.5)


def demo_summary() -> None:
    """Demonstrate log summarization."""
    from codesdevs_log_analyzer.analyzers.summarizer import summarize_log
    from codesdevs_log_analyzer.parsers import detect_format

    console.print("\n[bold green]━━━ Demo 4: Generate Summary ━━━[/bold green]\n")
    console.print("[dim]$ log_analyzer_summarize python_app.log[/dim]\n")
    time.sleep(0.5)

    from codesdevs_log_analyzer.models import LogFormat

    log_path = get_test_log_path("python_app.log")
    parser, _ = detect_format(str(log_path))

    summary = summarize_log(
        parser=parser,
        file_path=str(log_path),
        include_performance=True,
        include_security=True,
        detected_format=LogFormat.PYTHON,
        max_lines=1000,
    )

    # Level distribution chart
    console.print("[cyan]Level Distribution:[/cyan]")
    total = sum(summary.level_distribution.values())
    if total > 0:
        for level, count in sorted(summary.level_distribution.items(), key=lambda x: -x[1]):
            pct = (count / total) * 100
            bar_len = int(pct / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            color = "red" if "ERROR" in level else "yellow" if "WARN" in level else "green"
            console.print(f"  [{color}]{level:8}[/] {bar} {count:3} ({pct:4.1f}%)")

    # Recommendations
    if summary.recommendations:
        console.print("\n[cyan]Recommendations:[/cyan]")
        for rec in summary.recommendations[:3]:
            console.print(f"  [yellow]•[/yellow] {rec[:70]}")

    console.print("\n[green]✓[/green] Actionable insights for debugging")
    time.sleep(2)


def print_footer() -> None:
    """Print installation CTA."""
    footer = Text()
    footer.append("✓ Ready to analyze your logs?\n\n", style="bold green")
    footer.append("Install:\n", style="cyan")
    footer.append("$ uvx codesdevs-log-analyzer install\n\n", style="white")
    footer.append("Then in Claude Code:\n", style="cyan")
    footer.append('"Analyze /var/log/app.log and find the errors"\n\n', style="white dim")
    footer.append("github.com/Fato07/log-analyzer-mcp", style="dim")

    console.print(Panel(footer, border_style="green", padding=(1, 2)))


def run_demo() -> None:
    """Run the full demo sequence."""
    console.clear()

    print_banner()
    demo_parse()
    demo_search()
    demo_errors()
    demo_summary()
    print_footer()


if __name__ == "__main__":
    run_demo()
