#!/bin/bash
# Quickstart script for log-analyzer-mcp development
# Run this after cloning to set up the project

set -e

echo "🚀 Setting up log-analyzer-mcp development environment..."

# Check prerequisites
command -v uv >/dev/null 2>&1 || { echo "❌ uv is required. Install from https://docs.astral.sh/uv/"; exit 1; }
command -v git >/dev/null 2>&1 || { echo "❌ git is required"; exit 1; }

# Initialize git if not already
if [ ! -d ".git" ]; then
    echo "📦 Initializing git repository..."
    git init
    git add -A
    git commit -m "Initial commit: specs and project structure"
fi

# Create directory structure
echo "📁 Creating directory structure..."
mkdir -p log_analyzer_mcp/parsers
mkdir -p log_analyzer_mcp/analyzers
mkdir -p log_analyzer_mcp/utils
mkdir -p tests/test_parsers
mkdir -p tests/test_analyzers
mkdir -p test_logs

# Create __init__.py files
touch log_analyzer_mcp/__init__.py
touch log_analyzer_mcp/parsers/__init__.py
touch log_analyzer_mcp/analyzers/__init__.py
touch log_analyzer_mcp/utils/__init__.py
touch tests/__init__.py
touch tests/test_parsers/__init__.py
touch tests/test_analyzers/__init__.py

# Install dependencies
echo "📦 Installing dependencies..."
uv sync

# Verify installation
echo "✅ Verifying installation..."
uv run python -c "import mcp; print(f'MCP SDK version: {mcp.__version__}')"
uv run python -c "import pydantic; print(f'Pydantic version: {pydantic.__version__}')"

echo ""
echo "✨ Setup complete! Next steps:"
echo ""
echo "  Option 1: Run agents sequentially"
echo "  ─────────────────────────────────"
echo "  Open Claude Code and run the prompts from AGENTS.md"
echo ""
echo "  Option 2: Run agents in parallel (faster)"
echo "  ─────────────────────────────────────────"
echo "  # Create worktrees"
echo "  git worktree add ../log-analyzer-parsers -b feature/parsers"
echo "  git worktree add ../log-analyzer-analyzers -b feature/analyzers"
echo "  git worktree add ../log-analyzer-server -b feature/server"
echo ""
echo "  # Open separate terminals for each worktree and run Claude Code"
echo "  cd ../log-analyzer-parsers && claude"
echo "  cd ../log-analyzer-analyzers && claude"
echo "  cd ../log-analyzer-server && claude"
echo ""
echo "  See AGENTS.md for detailed prompts for each agent."
echo ""
echo "📚 Documentation:"
echo "  - CLAUDE.md    - Project context for Claude Code"
echo "  - SPEC.md      - Full specification"
echo "  - AGENTS.md    - Parallel agent execution guide"
echo "  - specs/       - Phase-by-phase implementation specs"
echo ""
