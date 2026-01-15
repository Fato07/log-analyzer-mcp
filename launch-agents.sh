#!/bin/bash
# 🚀 Parallel Agent Launcher for log-analyzer-mcp
# This script launches all Claude Code agents in parallel using Ralph Wiggum
# Safe to run multiple times - handles existing worktrees/branches
# Just run: ./launch-agents.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="log-analyzer-mcp"

echo "🚀 Log Analyzer MCP - Parallel Agent Launcher"
echo "=============================================="
echo ""

# Check prerequisites
command -v claude >/dev/null 2>&1 || { echo "❌ Claude Code CLI not found. Install it first."; exit 1; }
command -v git >/dev/null 2>&1 || { echo "❌ git is required"; exit 1; }
command -v uv >/dev/null 2>&1 || { echo "❌ uv is required. Install from https://docs.astral.sh/uv/"; exit 1; }

cd "$SCRIPT_DIR"

# Initialize git if needed
if [ ! -d ".git" ]; then
    echo "📦 Initializing git repository..."
    git init
    git add -A
    git commit -m "Initial commit: specs and project structure"
else
    echo "✅ Git repository already initialized"
fi

# Install dependencies first
echo "📦 Installing dependencies..."
uv sync || echo "⚠️  uv sync had issues, continuing anyway..."

# Create directory structure if missing
mkdir -p log_analyzer_mcp/parsers log_analyzer_mcp/analyzers log_analyzer_mcp/utils
mkdir -p tests/test_parsers tests/test_analyzers test_logs
touch log_analyzer_mcp/__init__.py log_analyzer_mcp/parsers/__init__.py
touch log_analyzer_mcp/analyzers/__init__.py log_analyzer_mcp/utils/__init__.py
touch tests/__init__.py tests/test_parsers/__init__.py tests/test_analyzers/__init__.py

# Commit any new files
git add -A
git diff --cached --quiet || git commit -m "Setup directory structure"

# Function to setup worktree (idempotent)
setup_worktree() {
    local worktree_path=$1
    local branch_name=$2
    
    # Check if worktree already exists
    if [ -d "$worktree_path" ]; then
        echo "   ✅ Worktree $worktree_path already exists"
    else
        # Check if branch exists
        if git show-ref --verify --quiet "refs/heads/$branch_name"; then
            echo "   🌳 Creating worktree from existing branch $branch_name..."
            git worktree add "$worktree_path" "$branch_name"
        else
            echo "   🌳 Creating worktree with new branch $branch_name..."
            git worktree add "$worktree_path" -b "$branch_name"
        fi
    fi
    
    # Copy specs and docs to worktree (always refresh)
    echo "   📄 Copying specs to $worktree_path..."
    cp -r specs "$worktree_path/" 2>/dev/null || true
    cp CLAUDE.md AGENTS.md README.md pyproject.toml "$worktree_path/" 2>/dev/null || true
}

# Prune any stale worktree references
echo ""
echo "🌳 Setting up git worktrees..."
git worktree prune 2>/dev/null || true

setup_worktree "../log-analyzer-parsers" "feature/parsers"
setup_worktree "../log-analyzer-analyzers" "feature/analyzers"
setup_worktree "../log-analyzer-server" "feature/server"

echo ""
echo "✅ Worktrees ready:"
echo "   - ../log-analyzer-parsers (feature/parsers)"
echo "   - ../log-analyzer-analyzers (feature/analyzers)"
echo "   - ../log-analyzer-server (feature/server)"

# Create prompt files in each worktree for easy copy-paste
cat > ../log-analyzer-parsers/PROMPT.txt << 'PROMPT_END'
/ralph-loop "TASK: Implement Phase 1 (Infrastructure) and Phase 2 (Parsers) for log-analyzer-mcp.

Read specs/phase1-infrastructure.md and specs/phase2-parsers.md carefully.
Also read CLAUDE.md for full project context.

EXECUTION ORDER:
1. Ensure pyproject.toml has all dependencies, run uv sync
2. Implement log_analyzer_mcp/models.py (all Pydantic models)
3. Implement log_analyzer_mcp/utils/time_utils.py
4. Implement log_analyzer_mcp/utils/file_handler.py
5. Implement log_analyzer_mcp/utils/formatters.py
6. Implement log_analyzer_mcp/parsers/base.py
7. Implement each parser: syslog, apache, jsonl, python_log, java, docker, kubernetes, generic
8. Implement parser registry in log_analyzer_mcp/parsers/__init__.py
9. Create test_logs/ sample files for each format
10. Write tests in tests/test_utils.py and tests/test_parsers/
11. Run tests and fix any failures
12. Commit all changes with message: Complete Phase 1+2: Infrastructure and Parsers

SUCCESS CRITERIA:
- All files created as specified in CLAUDE.md
- uv sync completes without errors
- uv run pytest tests/test_utils.py passes
- uv run pytest tests/test_parsers/ passes
- uv run mypy log_analyzer_mcp/parsers log_analyzer_mcp/utils log_analyzer_mcp/models.py passes

When ALL criteria are met, output: PARSERS_COMPLETE" --max-iterations 30 --completion-promise "PARSERS_COMPLETE"
PROMPT_END

cat > ../log-analyzer-analyzers/PROMPT.txt << 'PROMPT_END'
/ralph-loop "TASK: Implement Phase 3 (Analyzers) for log-analyzer-mcp.

Read specs/phase3-analyzers.md carefully.
Also read CLAUDE.md for full project context.

DEPENDENCY CHECK: First verify these files exist (created by another agent):
- log_analyzer_mcp/models.py
- log_analyzer_mcp/parsers/base.py

If they do not exist yet, wait 60 seconds and check again. Repeat up to 10 times.
If still missing after 10 minutes, proceed anyway and create minimal stubs.

EXECUTION ORDER:
1. Pull latest: git fetch origin and git merge origin/feature/parsers --no-edit (ignore errors)
2. Verify dependencies exist, wait if needed
3. Implement log_analyzer_mcp/analyzers/error_extractor.py
4. Implement log_analyzer_mcp/analyzers/pattern_matcher.py
5. Implement log_analyzer_mcp/analyzers/summarizer.py
6. Implement log_analyzer_mcp/analyzers/correlator.py
7. Create log_analyzer_mcp/analyzers/__init__.py with exports
8. Write tests in tests/test_analyzers/
9. Run tests and fix failures
10. Commit with message: Complete Phase 3: Analyzers

SUCCESS CRITERIA:
- All analyzer files created
- uv run pytest tests/test_analyzers/ passes
- uv run mypy log_analyzer_mcp/analyzers passes

When ALL criteria are met, output: ANALYZERS_COMPLETE" --max-iterations 25 --completion-promise "ANALYZERS_COMPLETE"
PROMPT_END

cat > ../log-analyzer-server/PROMPT.txt << 'PROMPT_END'
/ralph-loop "TASK: Implement Phase 4 (MCP Server and Tools) for log-analyzer-mcp.

Read specs/phase4-server.md carefully.
Also read CLAUDE.md for full project context.

DEPENDENCY CHECK: First verify these exist (created by other agents):
- log_analyzer_mcp/parsers/ (with multiple parser files)
- log_analyzer_mcp/analyzers/ (with analyzer files)

If they do not exist yet, wait 60 seconds and check again. Repeat up to 15 times.
If still missing after 15 minutes, proceed and create minimal implementations.

EXECUTION ORDER:
1. Pull latest: git fetch origin and git merge origin/feature/parsers origin/feature/analyzers --no-edit (ignore errors)
2. Verify dependencies exist, wait if needed
3. Implement log_analyzer_mcp/server.py with FastMCP setup
4. Implement tool: log_analyzer_parse
5. Implement tool: log_analyzer_search
6. Implement tool: log_analyzer_extract_errors
7. Implement tool: log_analyzer_summarize
8. Implement tool: log_analyzer_tail
9. Implement tool: log_analyzer_correlate
10. Implement tool: log_analyzer_diff
11. Create log_analyzer_mcp/__init__.py with exports
12. Write integration tests in tests/test_server.py
13. Verify server starts: uv run python -c 'from log_analyzer_mcp.server import mcp; print(OK)'
14. Commit with message: Complete Phase 4: Server and Tools

SUCCESS CRITERIA:
- All 7 tools implemented with proper MCP annotations
- uv run pytest tests/test_server.py passes
- Server module imports without errors

When ALL criteria are met, output: SERVER_COMPLETE" --max-iterations 30 --completion-promise "SERVER_COMPLETE"
PROMPT_END

echo ""
echo "========================================"
echo "📋 READY TO LAUNCH"
echo "========================================"
echo ""
echo "Each worktree now has a PROMPT.txt file."
echo "Open 3 terminals and run:"
echo ""
echo "  Terminal 1:"
echo "    cd ../log-analyzer-parsers && claude"
echo "    Then paste contents of PROMPT.txt (or run: cat PROMPT.txt)"
echo ""
echo "  Terminal 2:"
echo "    cd ../log-analyzer-analyzers && claude"
echo "    Then paste contents of PROMPT.txt"
echo ""
echo "  Terminal 3:"
echo "    cd ../log-analyzer-server && claude"
echo "    Then paste contents of PROMPT.txt"
echo ""
echo "📦 When all complete, run: ./finalize.sh"
echo ""
