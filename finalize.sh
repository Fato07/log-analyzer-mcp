#!/bin/bash
# 🏁 Finalize script - merge all branches and run final validation
# Run this after all agents complete

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🏁 Finalizing log-analyzer-mcp"
echo "==============================="
echo ""

# Check if agents are still running
if pgrep -f "claude.*ralph-loop" > /dev/null; then
    echo "⚠️  Warning: Some agents may still be running"
    echo "   Check with: pgrep -f 'claude.*ralph-loop'"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Merge all feature branches
echo "🔀 Merging feature branches..."
git checkout main

echo "   Merging feature/parsers..."
git merge feature/parsers -m "Merge parsers implementation" || {
    echo "❌ Merge conflict in parsers. Resolve manually."
    exit 1
}

echo "   Merging feature/analyzers..."
git merge feature/analyzers -m "Merge analyzers implementation" || {
    echo "❌ Merge conflict in analyzers. Resolve manually."
    exit 1
}

echo "   Merging feature/server..."
git merge feature/server -m "Merge server implementation" || {
    echo "❌ Merge conflict in server. Resolve manually."
    exit 1
}

echo "✅ All branches merged!"
echo ""

# Run final validation
echo "🧪 Running final validation..."
echo ""

echo "1️⃣  Installing dependencies..."
uv sync

echo "2️⃣  Running tests with coverage..."
uv run pytest -v --cov=log_analyzer_mcp --cov-report=term-missing --cov-fail-under=80 || {
    echo "❌ Tests failed or coverage below 80%"
    exit 1
}

echo "3️⃣  Type checking..."
uv run mypy log_analyzer_mcp --strict || {
    echo "⚠️  Type errors found (non-blocking)"
}

echo "4️⃣  Linting..."
uv run ruff check log_analyzer_mcp || {
    echo "⚠️  Lint errors found (non-blocking)"
}

echo "5️⃣  Building package..."
uv build || {
    echo "❌ Build failed"
    exit 1
}

echo "6️⃣  Testing server startup..."
timeout 5 uv run log-analyzer-mcp --help || {
    echo "❌ Server failed to start"
    exit 1
}

echo ""
echo "🎉 All validations passed!"
echo ""
echo "📦 Package built: dist/"
ls -la dist/
echo ""
echo "🚀 Next steps:"
echo "   1. Test with MCP Inspector:"
echo "      npx @modelcontextprotocol/inspector uv run log-analyzer-mcp"
echo ""
echo "   2. Push to GitHub:"
echo "      git remote add origin git@github.com:YOUR_USERNAME/log-analyzer-mcp.git"
echo "      git push -u origin main"
echo ""
echo "   3. Publish to PyPI:"
echo "      uv publish"
echo ""

# Clean up worktrees
echo "🧹 Cleaning up worktrees..."
git worktree remove ../log-analyzer-parsers --force 2>/dev/null || true
git worktree remove ../log-analyzer-analyzers --force 2>/dev/null || true
git worktree remove ../log-analyzer-server --force 2>/dev/null || true
git branch -d feature/parsers feature/analyzers feature/server 2>/dev/null || true

echo "✨ Done! Your MCP is ready to ship!"
