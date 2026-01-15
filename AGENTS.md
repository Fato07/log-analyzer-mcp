# Parallel Agent Execution Guide

This document describes how to run multiple Claude Code agents in parallel to build the log-analyzer-mcp faster.

## Prerequisites

1. Install Ralph Loop plugin (run this inside Claude Code):
```
/plugin install ralph-loop@claude-plugins-official
```

Reference: https://awesomeclaude.ai/ralph-wiggum

2. Set up git worktrees for parallel development:
```bash
cd log-analyzer-mcp
git init
git add -A
git commit -m "Initial spec commit"

# Create worktrees for parallel work
git worktree add ../log-analyzer-parsers -b feature/parsers
git worktree add ../log-analyzer-analyzers -b feature/analyzers
git worktree add ../log-analyzer-server -b feature/server
```

## Agent 1: Infrastructure + Parsers (Main Thread)

**Directory:** `log-analyzer-mcp/` (main)

**Prompt:**
```
/ralph-loop "
TASK: Implement Phase 1 (Infrastructure) and Phase 2 (Parsers) for log-analyzer-mcp.

Read specs/phase1-infrastructure.md and specs/phase2-parsers.md carefully.

EXECUTION ORDER:
1. Create pyproject.toml with all dependencies
2. Implement log_analyzer_mcp/models.py (all Pydantic models)
3. Implement log_analyzer_mcp/utils/time_utils.py
4. Implement log_analyzer_mcp/utils/file_handler.py
5. Implement log_analyzer_mcp/utils/formatters.py
6. Implement log_analyzer_mcp/parsers/base.py
7. Implement each parser: syslog, apache, jsonl, python_log, java, docker, kubernetes, generic
8. Implement parser registry in log_analyzer_mcp/parsers/__init__.py
9. Create test_logs/ sample files for each format
10. Write tests for all utilities and parsers

SUCCESS CRITERIA:
- All files created as specified in CLAUDE.md
- uv sync completes without errors
- uv run pytest tests/test_utils.py passes
- uv run pytest tests/test_parsers/ passes with >90% coverage
- uv run mypy log_analyzer_mcp/parsers log_analyzer_mcp/utils log_analyzer_mcp/models.py has zero errors

When ALL criteria are met, output: <promise>PARSERS_COMPLETE</promise>
" --max-iterations 30 --completion-promise "PARSERS_COMPLETE"
```

## Agent 2: Analyzers (Parallel Thread)

**Directory:** `../log-analyzer-analyzers/`

**Prerequisites:** Wait for Agent 1 to complete models.py and parsers/base.py, then:
```bash
git checkout main
git pull
git checkout feature/analyzers
git merge main
```

**Prompt:**
```
/ralph-loop "
TASK: Implement Phase 3 (Analyzers) for log-analyzer-mcp.

Read specs/phase3-analyzers.md carefully.

PREREQUISITES: models.py and parsers/ must exist (merge from main if needed).

EXECUTION ORDER:
1. Implement log_analyzer_mcp/analyzers/error_extractor.py
2. Implement log_analyzer_mcp/analyzers/pattern_matcher.py  
3. Implement log_analyzer_mcp/analyzers/summarizer.py
4. Implement log_analyzer_mcp/analyzers/correlator.py
5. Create log_analyzer_mcp/analyzers/__init__.py with exports
6. Write comprehensive tests in tests/test_analyzers/

SUCCESS CRITERIA:
- All analyzer files created
- uv run pytest tests/test_analyzers/ passes with >85% coverage
- uv run mypy log_analyzer_mcp/analyzers has zero errors
- Error grouping correctly identifies similar messages
- Pattern matching works with both regex and plain text

When ALL criteria are met, output: <promise>ANALYZERS_COMPLETE</promise>
" --max-iterations 25 --completion-promise "ANALYZERS_COMPLETE"
```

## Agent 3: Server + Tools (Parallel Thread)

**Directory:** `../log-analyzer-server/`

**Prerequisites:** Wait for Agent 1 AND Agent 2, then merge:
```bash
git checkout main
git pull
git checkout feature/server
git merge main
git merge feature/analyzers
```

**Prompt:**
```
/ralph-loop "
TASK: Implement Phase 4 (MCP Server & Tools) for log-analyzer-mcp.

Read specs/phase4-server.md carefully.

PREREQUISITES: parsers/ and analyzers/ must exist (merge from main if needed).

EXECUTION ORDER:
1. Implement log_analyzer_mcp/server.py with FastMCP setup
2. Implement log_analyzer_parse tool
3. Implement log_analyzer_search tool
4. Implement log_analyzer_extract_errors tool
5. Implement log_analyzer_summarize tool
6. Implement log_analyzer_tail tool
7. Implement log_analyzer_correlate tool
8. Implement log_analyzer_diff tool
9. Create log_analyzer_mcp/__init__.py with exports
10. Write integration tests in tests/test_server.py

SUCCESS CRITERIA:
- Server runs: uv run log-analyzer-mcp --help works
- All 7 tools have proper annotations
- All tools support markdown and json output
- uv run pytest tests/test_server.py passes
- npx @modelcontextprotocol/inspector shows all tools correctly

When ALL criteria are met, output: <promise>SERVER_COMPLETE</promise>
" --max-iterations 30 --completion-promise "SERVER_COMPLETE"
```

## Agent 4: Testing & Documentation (Final Thread)

**Directory:** `log-analyzer-mcp/` (main, after merging all features)

**Prerequisites:** Merge all feature branches:
```bash
git checkout main
git merge feature/parsers
git merge feature/analyzers  
git merge feature/server
```

**Prompt:**
```
/ralph-loop "
TASK: Complete Phase 5 (Testing & Documentation) for log-analyzer-mcp.

Read specs/phase5-testing-docs.md carefully.

PREREQUISITES: All code must be merged into main branch.

EXECUTION ORDER:
1. Create comprehensive test fixtures in tests/conftest.py
2. Add edge case tests for all parsers
3. Add edge case tests for all analyzers
4. Add integration tests for all tools
5. Create test_logs/ sample files if missing
6. Write README.md with installation, usage, examples
7. Write CHANGELOG.md
8. Create LICENSE file (MIT)
9. Verify test coverage >80%
10. Fix any linter/type errors

SUCCESS CRITERIA:
- uv run pytest --cov --cov-fail-under=80 passes
- uv run ruff check log_analyzer_mcp has zero errors
- uv run mypy log_analyzer_mcp --strict has zero errors
- README.md has all sections (installation, usage, examples)
- uv build creates package successfully
- Package installs and runs correctly

When ALL criteria are met, output: <promise>RELEASE_READY</promise>
" --max-iterations 25 --completion-promise "RELEASE_READY"
```

## Sequential Execution (Alternative)

If you prefer not to use worktrees, run agents sequentially in main directory:

```bash
# Phase 1 + 2
/ralph-loop "... (Agent 1 prompt) ..." --max-iterations 30

# After completion:
# Phase 3
/ralph-loop "... (Agent 2 prompt) ..." --max-iterations 25

# After completion:
# Phase 4  
/ralph-loop "... (Agent 3 prompt) ..." --max-iterations 30

# After completion:
# Phase 5
/ralph-loop "... (Agent 4 prompt) ..." --max-iterations 25
```

## Monitoring Progress

Open separate terminal for monitoring:

```bash
# Watch test results
watch -n 30 'cd /path/to/log-analyzer-mcp && uv run pytest --tb=no -q 2>/dev/null || echo "Tests not ready"'

# Watch coverage
watch -n 60 'cd /path/to/log-analyzer-mcp && uv run pytest --cov=log_analyzer_mcp --cov-report=term-missing -q 2>/dev/null | tail -20'
```

## Troubleshooting

### Agent stuck in loop
```bash
/cancel-ralph
```

### Merge conflicts
Resolve manually, then re-run the agent prompt.

### Tests failing
Check the test output, fix issues manually or add to the prompt:
```
ADDITIONAL CONTEXT: Previous iteration failed with: [paste error]
Fix this issue before continuing.
```

### API rate limits
If hitting limits, add delay between iterations:
```bash
# In the prompt, add:
"After each major step, pause for 5 seconds to avoid rate limits."
```
