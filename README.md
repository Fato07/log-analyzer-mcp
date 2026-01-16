# Log Analyzer MCP

<!-- mcp-name: io.github.Fato07/log-analyzer-mcp -->

[![MCP Registry](https://img.shields.io/badge/MCP-Registry-green?logo=anthropic)](https://registry.modelcontextprotocol.io/servers/io.github.Fato07/log-analyzer-mcp)
[![PyPI version](https://badge.fury.io/py/codesdevs-log-analyzer.svg)](https://badge.fury.io/py/codesdevs-log-analyzer)
[![PyPI Downloads](https://static.pepy.tech/badge/codesdevs-log-analyzer)](https://pepy.tech/project/codesdevs-log-analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![GitHub stars](https://img.shields.io/github/stars/Fato07/log-analyzer-mcp?style=social)](https://github.com/Fato07/log-analyzer-mcp)

> 🔍 **Stop copy-pasting logs into AI.** Let Claude read them directly.

An MCP server for AI-powered log analysis. Parse, search, and debug log files across 9+ formats — right from Claude Code.

## 📊 At a Glance

| | |
|---|---|
| **14** MCP tools | **9+** log formats |
| **280** tests | **81%+** coverage |

## 🎬 Demo

![Log Analyzer MCP Demo](demo/demo.gif)

*Analyzing logs with 14 specialized tools*

## 🤔 Why?

| Without log-analyzer-mcp | With log-analyzer-mcp |
|--------------------------|----------------------|
| Copy-paste chunks of logs | Point Claude at the file |
| Lose context between pastes | Full file access |
| Manual format parsing | Auto-detection |
| Miss related errors | Smart correlation |

## ✨ Features

- **Auto-Detection** — Identifies format from 9+ common log types
- **Smart Search** — Pattern matching with context, regex, and time filtering
- **Error Extraction** — Groups similar errors, captures stack traces
- **Natural Language** — Ask questions like "what errors happened today?"
- **Sensitive Data Scan** — Detect PII, credentials, and secrets
- **Multi-File Analysis** — Correlate events across distributed systems
- **Streaming** — Handles 1GB+ files without memory issues

## 🚀 Quick Start

```bash
# Install (adds to Claude Code automatically)
uvx codesdevs-log-analyzer install
```

Then in Claude Code:

```
Analyze /var/log/app.log and tell me what's causing the errors
```

## 📦 Installation

### One-liner (Recommended)

```bash
uvx codesdevs-log-analyzer install
```

### Manual

<details>
<summary>pip / uv / Claude Code config</summary>

```bash
# pip
pip install codesdevs-log-analyzer

# uv
uv tool install codesdevs-log-analyzer
```

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "log-analyzer": {
      "command": "uvx",
      "args": ["codesdevs-log-analyzer"]
    }
  }
}
```

</details>

## 📋 Supported Formats

| Format | Example |
|--------|---------|
| Syslog | `Jan 15 10:30:00 hostname process[pid]: message` |
| Apache/Nginx | `127.0.0.1 - - [15/Jan/2026:10:30:00] "GET /path" 200` |
| JSON Lines | `{"timestamp": "...", "level": "ERROR", "message": "..."}` |
| Docker | `2026-01-15T10:30:00.123Z stdout message` |
| Python | `2026-01-15 10:30:00,123 - module - ERROR - message` |
| Java/Log4j | `2026-01-15 10:30:00,123 ERROR [thread] class - message` |
| Kubernetes | `level=error msg="..." ts=2026-01-15T10:30:00Z` |
| Generic | Any line with recognizable timestamp |

## ⚡ Performance

| Metric | Value |
|--------|-------|
| 100MB log file | < 10 seconds |
| Memory footprint | Streaming (no full load) |
| Max tested size | 1GB+ |
| Format detection | < 100ms |

## 🛠️ Available Tools

| Tool | Description |
|------|-------------|
| `log_analyzer_parse` | Detect format and extract metadata |
| `log_analyzer_search` | Search with context lines |
| `log_analyzer_extract_errors` | Extract and group errors |
| `log_analyzer_summarize` | Generate debugging summary |
| `log_analyzer_correlate` | Find related events |
| `log_analyzer_watch` | Monitor for new entries |
| `log_analyzer_ask` | Natural language queries |
| `log_analyzer_scan_sensitive` | Detect PII/credentials |
| + 6 more | [Full reference →](docs/TOOLS.md) |

## 💡 Examples

**Find errors:**
```
Extract all errors from /var/log/app.log, group similar ones
```

**Search with context:**
```
Search for "timeout" in app.log with 5 lines of context
```

**Correlate events:**
```
What happened 60 seconds before each OutOfMemoryError?
```

**Scan for secrets:**
```
Check /var/log/app.log for accidentally logged credentials
```

## 🔧 Development

```bash
git clone https://github.com/Fato07/log-analyzer-mcp
cd log-analyzer-mcp
uv sync
uv run pytest -v --cov
```

## 📈 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Fato07/log-analyzer-mcp&type=Date)](https://star-history.com/#Fato07/log-analyzer-mcp&Date)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Found this useful?</b> Give it a ⭐ on GitHub!<br><br>
  <a href="https://github.com/Fato07/log-analyzer-mcp/issues/new?template=bug_report.yml">Report bugs</a> ·
  <a href="https://github.com/Fato07/log-analyzer-mcp/issues/new?template=feature_request.yml">Request features</a> ·
  <a href="https://github.com/Fato07/log-analyzer-mcp/discussions">Discussions</a> ·
  <a href="https://github.com/Fato07/log-analyzer-mcp/blob/main/docs/TOOLS.md">Full docs</a>
</p>

<p align="center">
  Built by <a href="https://github.com/Fato07">Fato07</a> at <a href="https://codesdevs.io">CodesDevs</a>
</p>
