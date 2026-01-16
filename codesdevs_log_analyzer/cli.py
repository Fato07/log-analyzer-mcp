"""CLI entry point for codesdevs-log-analyzer.

Provides install/uninstall commands for auto-configuring Claude Code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Support both config locations
CLAUDE_JSON = Path.home() / ".claude.json"
CLAUDE_SETTINGS = Path.home() / ".claude" / "settings.json"

MCP_CONFIG = {
    "command": "uvx",
    "args": ["codesdevs-log-analyzer"]
}


def get_config_path() -> Path:
    """Get the Claude Code config file path.

    Checks both possible locations and returns the one that exists.
    If neither exists, defaults to ~/.claude.json (more common).
    """
    if CLAUDE_JSON.exists():
        return CLAUDE_JSON
    if CLAUDE_SETTINGS.exists():
        return CLAUDE_SETTINGS
    # Default to ~/.claude.json if neither exists
    return CLAUDE_JSON


def install() -> None:
    """Add MCP server to Claude Code settings."""
    config_path = get_config_path()

    settings: dict[str, object] = {}
    if config_path.exists():
        settings = json.loads(config_path.read_text())

    if "mcpServers" not in settings:
        settings["mcpServers"] = {}

    mcp_servers = settings["mcpServers"]
    if isinstance(mcp_servers, dict):
        mcp_servers["log-analyzer"] = MCP_CONFIG

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(settings, indent=2) + "\n")

    print(f"✓ Added log-analyzer to {config_path}")
    print("  Restart Claude Code to use the new MCP server")


def uninstall() -> None:
    """Remove MCP server from Claude Code settings."""
    config_path = get_config_path()

    if not config_path.exists():
        print("No Claude Code settings found")
        return

    settings = json.loads(config_path.read_text())
    mcp_servers = settings.get("mcpServers", {})

    if isinstance(mcp_servers, dict) and "log-analyzer" in mcp_servers:
        del mcp_servers["log-analyzer"]
        config_path.write_text(json.dumps(settings, indent=2) + "\n")
        print(f"✓ Removed log-analyzer from {config_path}")
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
    print("  codesdevs-log-analyzer demo      Run interactive demo")
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
    elif sys.argv[1] == "demo":
        from codesdevs_log_analyzer.demo import run_demo

        run_demo()
    elif sys.argv[1] in ("--help", "-h", "help"):
        show_help()
    else:
        print(f"Unknown command: {sys.argv[1]}")
        show_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
