"""CLI entry point for codesdevs-log-analyzer.

Provides install/uninstall commands for auto-configuring Claude Code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"

MCP_CONFIG = {
    "command": "uvx",
    "args": ["codesdevs-log-analyzer"]
}


def install() -> None:
    """Add MCP server to Claude Code settings."""
    settings: dict[str, object] = {}
    if CLAUDE_SETTINGS.exists():
        settings = json.loads(CLAUDE_SETTINGS.read_text())

    if "mcpServers" not in settings:
        settings["mcpServers"] = {}

    mcp_servers = settings["mcpServers"]
    if isinstance(mcp_servers, dict):
        mcp_servers["log-analyzer"] = MCP_CONFIG

    CLAUDE_SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    CLAUDE_SETTINGS.write_text(json.dumps(settings, indent=2) + "\n")

    print("✓ Added log-analyzer to Claude Code")
    print("  Restart Claude Code to use the new MCP server")


def uninstall() -> None:
    """Remove MCP server from Claude Code settings."""
    if not CLAUDE_SETTINGS.exists():
        print("No Claude Code settings found")
        return

    settings = json.loads(CLAUDE_SETTINGS.read_text())
    mcp_servers = settings.get("mcpServers", {})

    if isinstance(mcp_servers, dict) and "log-analyzer" in mcp_servers:
        del mcp_servers["log-analyzer"]
        CLAUDE_SETTINGS.write_text(json.dumps(settings, indent=2) + "\n")
        print("✓ Removed log-analyzer from Claude Code")
    else:
        print("log-analyzer not found in settings")


def show_help() -> None:
    """Display usage information."""
    print("codesdevs-log-analyzer - AI-powered log analysis MCP server")
    print()
    print("Usage:")
    print("  codesdevs-log-analyzer           Run the MCP server")
    print("  codesdevs-log-analyzer install   Add to Claude Code settings")
    print("  codesdevs-log-analyzer uninstall Remove from Claude Code settings")
    print("  codesdevs-log-analyzer --help    Show this help message")


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) < 2:
        # No args = run server
        from codesdevs_log_analyzer.server import main as server_main
        server_main()
    elif sys.argv[1] == "install":
        install()
    elif sys.argv[1] == "uninstall":
        uninstall()
    elif sys.argv[1] in ("--help", "-h", "help"):
        show_help()
    else:
        print(f"Unknown command: {sys.argv[1]}")
        show_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
