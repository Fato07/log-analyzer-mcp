# Contributing to Log Analyzer MCP

Thank you for your interest in contributing to log-analyzer-mcp! This document provides guidelines and instructions for contributing.

## Quick Start (TL;DR)

For experienced developers:

```bash
git clone https://github.com/YOUR_USERNAME/log-analyzer-mcp.git
cd log-analyzer-mcp
uv sync
uv run pytest -v --cov          # Run tests
uv run ruff check .             # Lint
uv run mypy log_analyzer_mcp    # Type check
```

## Prerequisites

- **Python 3.10+** — [Download](https://www.python.org/downloads/)
- **uv** — [Install guide](https://docs.astral.sh/uv/getting-started/installation/)
- **git** — [Download](https://git-scm.com/downloads)

## Development Setup

### 1. Fork and Clone

```bash
# Fork via GitHub UI, then:
git clone https://github.com/YOUR_USERNAME/log-analyzer-mcp.git
cd log-analyzer-mcp
```

### 2. Install Dependencies

```bash
uv sync
```

This installs all dependencies including dev tools (pytest, ruff, mypy).

### 3. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 4. Verify Setup

```bash
uv run pytest -v
```

All tests should pass before you start making changes.

## Code Style

### Type Hints

Type hints are **required** for all functions and methods:

```python
# Good
def parse_log(file_path: str, max_lines: int = 1000) -> list[LogEntry]:
    ...

# Bad - missing type hints
def parse_log(file_path, max_lines=1000):
    ...
```

### Linting & Formatting

We use **ruff** for linting and formatting:

```bash
# Check for issues
uv run ruff check .

# Auto-fix issues
uv run ruff check --fix .

# Format code
uv run ruff format .
```

### Type Checking

We use **mypy** in strict mode:

```bash
uv run mypy log_analyzer_mcp
```

All code must pass with zero errors.

### Docstrings

Use Google-style docstrings:

```python
def extract_errors(
    file_path: str,
    include_warnings: bool = False,
) -> ErrorExtractionResult:
    """Extract and group errors from a log file.

    Args:
        file_path: Path to the log file to analyze.
        include_warnings: Whether to include WARNING level entries.

    Returns:
        ErrorExtractionResult containing grouped errors and statistics.

    Raises:
        FileNotFoundError: If the log file doesn't exist.
        ParseError: If the log format cannot be detected.
    """
```

## Testing

### Running Tests

```bash
# Run all tests
uv run pytest -v

# Run with coverage
uv run pytest -v --cov=log_analyzer_mcp --cov-report=term-missing

# Run specific test file
uv run pytest tests/test_parsers/test_syslog.py -v

# Run tests matching a pattern
uv run pytest -k "test_error" -v
```

### Coverage Requirements

- **Minimum coverage: 80%**
- New features should include tests
- Bug fixes should include regression tests

### Manual Testing with MCP Inspector

Test your changes with the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector uv run codesdevs-log-analyzer
```

This launches an interactive UI to test MCP tools directly.

## Adding New Features

### New Log Format Parser

1. Create parser in `log_analyzer_mcp/parsers/`
2. Inherit from `BaseLogParser`
3. Implement `parse_line()` and `detect()` methods
4. Register in `log_analyzer_mcp/parsers/__init__.py`
5. Add tests in `tests/test_parsers/`
6. Add sample log file in `test_logs/`

### New MCP Tool

1. Add tool function in `log_analyzer_mcp/server.py`
2. Use `@mcp.tool()` decorator with annotations
3. Create Pydantic models for input/output in `models.py`
4. Add tests in `tests/test_server.py`
5. Document in `docs/TOOLS.md`

## Pull Request Process

### Before Submitting

1. **Open an issue first** — Discuss your idea before investing time (unless it's a trivial fix)
2. **One PR per feature/fix** — Keep PRs focused and reviewable
3. **Update documentation** — If you change behavior, update docs
4. **Add tests** — All new code needs tests
5. **Run the full test suite**:
   ```bash
   uv run pytest -v --cov
   uv run ruff check .
   uv run mypy log_analyzer_mcp
   ```

### PR Guidelines

- Use a descriptive title (e.g., "Add CloudWatch log format parser")
- Reference related issues (e.g., "Fixes #123")
- Describe what changed and why
- Include before/after examples if relevant

### Labels

PRs are auto-labeled by Release Drafter based on:
- `feature/*` branch → `enhancement` label
- `fix/*` branch → `bug` label
- Changes to `*.md` → `documentation` label

## AI Contributions

If you use **AI assistance** (ChatGPT, Claude, Copilot, etc.) when contributing:

**Required:**
- Disclose AI usage in your PR description
- Demonstrate understanding of the changes
- Provide test cases and evidence that changes work

**We will close PRs that:**
- Don't disclose AI assistance
- Show no evidence of human understanding
- Lack tests or examples

This follows MCP community standards for AI-assisted contributions.

## Good First Issues

New to the project? Look for issues labeled:
- [`good first issue`](https://github.com/Fato07/log-analyzer-mcp/labels/good%20first%20issue) — Great starting points
- [`help wanted`](https://github.com/Fato07/log-analyzer-mcp/labels/help%20wanted) — We'd love help with these

Easy ways to contribute:
- Add support for a new log format
- Improve error messages
- Add test cases
- Fix documentation typos

## Getting Help

- **Questions**: [GitHub Discussions](https://github.com/Fato07/log-analyzer-mcp/discussions)
- **Bugs**: [Open an issue](https://github.com/Fato07/log-analyzer-mcp/issues/new?template=bug_report.yml)
- **Features**: [Request a feature](https://github.com/Fato07/log-analyzer-mcp/issues/new?template=feature_request.yml)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

---

Thank you for contributing! Every improvement helps make log analysis easier for developers everywhere.
