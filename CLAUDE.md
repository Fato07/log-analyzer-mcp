# CLAUDE.md - Log Analyzer MCP Server

## Project Overview

**log-analyzer-mcp** is a public MCP (Model Context Protocol) server that helps AI assistants analyze, parse, and debug log files across various formats. Designed to handle large log files efficiently and provide intelligent insights for debugging.

**Target:** First public MCP release for CodesDevs - must be production-quality, well-tested, and documented.

## Tech Stack

- **Language:** Python 3.10+
- **Framework:** FastMCP (MCP Python SDK)
- **Validation:** Pydantic v2
- **Date Parsing:** python-dateutil
- **Encoding Detection:** chardet
- **Testing:** pytest, pytest-asyncio, pytest-cov
- **Linting:** ruff, mypy

## Project Structure

```
log-analyzer-mcp/
├── CLAUDE.md                 # This file
├── SPEC.md                   # Full specification
├── README.md                 # Public documentation
├── pyproject.toml            # Package configuration
├── log_analyzer_mcp/
│   ├── __init__.py
│   ├── server.py             # FastMCP server entry point
│   ├── models.py             # Pydantic models for all inputs/outputs
│   ├── parsers/
│   │   ├── __init__.py       # Parser registry and auto-detection
│   │   ├── base.py           # BaseLogParser abstract class
│   │   ├── syslog.py         # Syslog format parser
│   │   ├── apache.py         # Apache/Nginx access & error logs
│   │   ├── jsonl.py          # JSON Lines structured logs
│   │   ├── python_log.py     # Python logging format
│   │   ├── java.py           # Java/Log4j format
│   │   ├── docker.py         # Docker/container logs
│   │   └── generic.py        # Generic timestamp fallback
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── error_extractor.py
│   │   ├── pattern_matcher.py
│   │   ├── summarizer.py
│   │   └── correlator.py
│   └── utils/
│       ├── __init__.py
│       ├── file_handler.py   # Streaming file operations
│       ├── formatters.py     # Markdown/JSON output formatting
│       └── time_utils.py     # Timestamp parsing utilities
├── tests/
│   ├── __init__.py
│   ├── conftest.py           # Shared fixtures
│   ├── test_parsers/
│   │   ├── test_syslog.py
│   │   ├── test_apache.py
│   │   ├── test_jsonl.py
│   │   └── ...
│   ├── test_analyzers/
│   │   └── ...
│   ├── test_server.py        # Integration tests
│   └── test_utils.py
└── test_logs/                # Sample log files for testing
    ├── python_app.log
    ├── nginx_access.log
    ├── nginx_error.log
    ├── docker_container.log
    ├── kubernetes_pod.log
    ├── mixed_format.log
    └── malformed.log
```

## MCP Tools to Implement

| Tool Name | Purpose | Priority |
|-----------|---------|----------|
| `log_analyzer_parse` | Parse and detect log format, extract metadata | P0 |
| `log_analyzer_search` | Search patterns with context lines | P0 |
| `log_analyzer_extract_errors` | Extract all errors with stack traces | P0 |
| `log_analyzer_summarize` | Generate debugging summary | P1 |
| `log_analyzer_tail` | Get recent log entries | P1 |
| `log_analyzer_correlate` | Correlate events in time windows | P2 |
| `log_analyzer_diff` | Compare log files or time periods | P2 |

## Supported Log Formats

1. **Syslog** - `Jan 15 10:30:00 hostname process[pid]: message`
2. **Apache/Nginx Access** - Combined log format
3. **Apache/Nginx Error** - Error log format
4. **JSON Lines (JSONL)** - Structured logging
5. **Docker/Container** - Container stdout/stderr
6. **Python Logging** - Standard library format
7. **Java/Log4j** - Common Java logging
8. **Kubernetes** - K8s pod logs
9. **Generic Timestamp** - Fallback for any timestamped logs

## Coding Standards

### Python Style
- Use type hints everywhere
- Pydantic v2 for all input/output models
- Async functions for all I/O operations
- Use `Field()` with descriptions for all Pydantic fields
- Never load entire files into memory - use generators/streaming

### MCP Tool Standards
- All tools must have `name` and `annotations` in decorator
- Tool names prefixed with `log_analyzer_`
- Support both `markdown` and `json` response formats
- Include pagination for list operations
- Actionable error messages with suggestions

### Testing Requirements
- Minimum 80% code coverage
- Unit tests for each parser
- Integration tests for each tool
- Edge case tests (malformed input, large files, encoding issues)
- Use pytest fixtures for sample log files

## Key Design Decisions

1. **Streaming-first:** Never load entire file into memory. Use generators and process in chunks.

2. **Format auto-detection:** Try each parser on first 100 lines, score by parse success rate.

3. **Graceful degradation:** Malformed lines logged but don't break parsing.

4. **Context-aware:** When searching, always include surrounding lines for debugging context.

5. **Pattern grouping:** Similar errors grouped by message template to reduce noise.

## Commands Reference

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest -v --cov=log_analyzer_mcp --cov-report=term-missing

# Type checking
uv run mypy log_analyzer_mcp

# Linting
uv run ruff check log_analyzer_mcp

# Run server locally
uv run log-analyzer-mcp

# Test with MCP Inspector
npx @modelcontextprotocol/inspector uv run log-analyzer-mcp
```

## Success Criteria

- [ ] All 7 tools implemented and functional
- [ ] 9 log formats supported with >90% accuracy
- [ ] 100MB file processed in <10 seconds
- [ ] 80%+ test coverage
- [ ] Zero linter/type errors
- [ ] README with installation + usage examples
- [ ] Published to PyPI (manual step)

## Notes for Claude Code

- When implementing parsers, start with `base.py` to define the interface
- Test each parser individually before integrating
- Use the test_logs/ directory for integration testing
- Keep tool responses concise - Claude context limits matter
- Prioritize P0 tools, then P1, then P2
