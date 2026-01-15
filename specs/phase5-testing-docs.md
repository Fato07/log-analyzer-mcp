# Phase 5: Testing & Documentation

## Objective
Comprehensive testing, documentation, and release preparation.

## Test Coverage Requirements

### Minimum Coverage: 80%

**Coverage by Module:**
- `parsers/` - 90%+ (critical for accuracy)
- `analyzers/` - 85%+
- `utils/` - 85%+
- `server.py` - 80%+

### Test Categories

#### Unit Tests
**Location:** `tests/test_*.py`

1. **Parser Tests** (`tests/test_parsers/`)
   - Valid input parsing
   - Edge cases (missing fields, unusual formats)
   - Malformed input handling
   - Timestamp parsing accuracy
   - Stack trace detection

2. **Analyzer Tests** (`tests/test_analyzers/`)
   - Error grouping accuracy
   - Pattern matching (regex + plain text)
   - Anomaly detection
   - Correlation logic

3. **Utility Tests** (`tests/test_utils.py`)
   - File streaming
   - Encoding detection
   - Timestamp parsing
   - Output formatting

#### Integration Tests
**Location:** `tests/test_integration.py`

1. **End-to-end tool tests**
   - Each tool with sample logs
   - Both output formats (markdown, json)
   - Error handling

2. **Large file tests**
   - 10MB file processing
   - Memory usage verification
   - Performance benchmarks

#### Property-Based Tests (Optional)
**Location:** `tests/test_properties.py`

Using `hypothesis` library:
- Random valid log lines parse correctly
- Random timestamps are handled
- No crashes on any input

### Test Fixtures
**File:** `tests/conftest.py`

```python
import pytest
from pathlib import Path

@pytest.fixture
def sample_logs_dir(tmp_path) -> Path:
    """Create directory with sample log files."""
    pass

@pytest.fixture
def python_log_file(tmp_path) -> Path:
    """Create sample Python log file with errors."""
    pass

@pytest.fixture
def nginx_access_log(tmp_path) -> Path:
    """Create sample Nginx access log."""
    pass

@pytest.fixture
def large_log_file(tmp_path) -> Path:
    """Create 10MB log file for performance testing."""
    pass

@pytest.fixture
def mixed_format_log(tmp_path) -> Path:
    """Create log with mixed/malformed lines."""
    pass
```

### Sample Log Files
**Directory:** `test_logs/`

Create realistic test files:

1. **python_app.log** (500 lines)
   - Normal INFO messages
   - Warnings about deprecation
   - Errors with stack traces
   - Multi-line exception output

2. **nginx_access.log** (1000 lines)
   - Various HTTP methods
   - Mix of status codes (2xx, 3xx, 4xx, 5xx)
   - Different paths and user agents

3. **nginx_error.log** (200 lines)
   - Connection errors
   - Upstream timeouts
   - Permission issues

4. **docker_container.log** (500 lines)
   - stdout and stderr mixed
   - Partial message flags
   - JSON structured logs inside

5. **kubernetes_pod.log** (500 lines)
   - Key-value format
   - Nested JSON
   - Controller logs

6. **mixed_format.log** (200 lines)
   - Different formats mixed
   - Some malformed lines
   - Missing timestamps

7. **malformed.log** (100 lines)
   - Invalid timestamps
   - Truncated JSON
   - Binary content mixed in
   - Very long lines

## Documentation

### README.md
**File:** `README.md`

Structure:
1. **Header** - Name, badges (PyPI, license, coverage)
2. **Description** - What it does, why it's useful
3. **Features** - Supported formats, tools available
4. **Installation** - pip/uv/claude code setup
5. **Quick Start** - Basic usage examples
6. **Tools Reference** - Each tool with parameters
7. **Supported Formats** - Table of log formats
8. **Configuration** - Claude Code setup
9. **Contributing** - How to contribute
10. **License** - MIT

### Installation Instructions

```markdown
## Installation

### Using pip
```bash
pip install log-analyzer-mcp
```

### Using uv
```bash
uv tool install log-analyzer-mcp
```

### Claude Code Integration

Add to your `~/.claude/settings.json`:
```json
{
  "mcpServers": {
    "log-analyzer": {
      "command": "uvx",
      "args": ["log-analyzer-mcp"]
    }
  }
}
```

Or using pip installation:
```json
{
  "mcpServers": {
    "log-analyzer": {
      "command": "log-analyzer-mcp"
    }
  }
}
```
```

### Usage Examples

```markdown
## Usage Examples

### Analyze a log file
```
Analyze /var/log/app.log and tell me what's wrong
```
Claude will use `log_analyzer_parse` → `log_analyzer_extract_errors` → `log_analyzer_summarize`

### Search for specific errors
```
Search for "connection timeout" in /var/log/nginx/error.log with 5 lines of context
```

### Debug a specific issue
```
I'm seeing 502 errors. Look at /var/log/nginx/access.log and correlate what happens before each 502
```

### Compare deployments
```
Compare errors between /var/log/app.log.1 (yesterday) and /var/log/app.log (today)
```
```

### Tool Reference Documentation

For each tool, document:
- **Name** and purpose
- **Parameters** with types and defaults
- **Example input**
- **Example output**
- **Use cases**

### CHANGELOG.md
**File:** `CHANGELOG.md`

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-15

### Added
- Initial release
- 7 MCP tools for log analysis
- Support for 9 log formats
- Automatic format detection
- Error extraction with stack traces
- Pattern search with context
- Log summarization
- Event correlation
- File comparison
```

### LICENSE
**File:** `LICENSE`

MIT License

## Release Checklist

### Pre-Release
- [ ] All tests pass
- [ ] Coverage >80%
- [ ] Zero linter errors (`ruff check`)
- [ ] Zero type errors (`mypy`)
- [ ] README complete with examples
- [ ] CHANGELOG updated
- [ ] Version number correct in pyproject.toml

### Release Steps
```bash
# Final checks
uv run pytest --cov --cov-report=term-missing
uv run ruff check log_analyzer_mcp
uv run mypy log_analyzer_mcp

# Build package
uv build

# Test installation locally
uv pip install dist/log_analyzer_mcp-0.1.0-py3-none-any.whl

# Test with MCP Inspector
npx @modelcontextprotocol/inspector log-analyzer-mcp

# Publish to PyPI (manual)
uv publish
```

### Post-Release
- [ ] Create GitHub release with notes
- [ ] Announce on Twitter/LinkedIn
- [ ] Submit to MCP server registries
- [ ] Gather feedback

## Success Criteria
- [ ] 80%+ test coverage
- [ ] All tests pass
- [ ] Zero linter/type errors
- [ ] README has installation + usage + examples
- [ ] CHANGELOG documents all features
- [ ] Package builds successfully
- [ ] Server runs with MCP Inspector
- [ ] Ready for PyPI publish

## Test Commands
```bash
# Full test suite with coverage
uv run pytest -v --cov=log_analyzer_mcp --cov-report=term-missing --cov-report=html

# Type checking
uv run mypy log_analyzer_mcp --strict

# Linting
uv run ruff check log_analyzer_mcp
uv run ruff format --check log_analyzer_mcp

# Build verification
uv build
```
