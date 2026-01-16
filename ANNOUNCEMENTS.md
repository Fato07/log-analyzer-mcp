# Social Media Announcements

## X/Twitter

### Short version (280 chars)
```
Just published log-analyzer-mcp to the official MCP Registry!

AI-powered log analysis for Claude Code:
- Parse 9+ log formats
- Extract errors & stack traces
- Natural language queries
- Sensitive data detection

https://github.com/Fato07/log-analyzer-mcp
```

### Thread version
```
1/ Just shipped log-analyzer-mcp to the official @AnthropicAI MCP Registry!

It's an AI-powered log analyzer that works directly in Claude Code.

Here's what it can do:

2/ Auto-detects 9+ log formats:
- Syslog
- Apache/Nginx
- JSON Lines
- Python logging
- Java/Log4j
- Docker/K8s
- And more...

No config needed - just point it at your logs.

3/ Smart features:
- Extract & group similar errors
- Capture stack traces automatically
- Search with context lines
- Natural language queries ("what errors happened today?")
- Correlate events across files

4/ Security built-in:
- Scan for PII, credentials, secrets
- Detect API keys, JWTs, passwords
- Optional redaction mode

5/ Handles enterprise scale:
- Streams 1GB+ files without memory issues
- Process 100MB in <10 seconds
- Multi-file correlation

Try it:
uvx codesdevs-log-analyzer install

GitHub: https://github.com/Fato07/log-analyzer-mcp
MCP Registry: https://registry.modelcontextprotocol.io
```

---

## Reddit r/programming

### Title
```
I built an MCP server for AI-powered log analysis - now on the official MCP Registry
```

### Body
```
Hey r/programming!

Just published my first MCP (Model Context Protocol) server to the official registry. It lets AI assistants like Claude analyze log files directly.

**What it does:**
- Auto-detects 9+ log formats (syslog, Apache, JSON Lines, Python, Java, Docker, K8s)
- Extracts and groups similar errors with stack traces
- Natural language queries ("what caused the 502 errors?")
- Sensitive data detection (PII, API keys, credentials)
- Multi-file correlation for distributed systems
- Handles 1GB+ files via streaming

**Why I built it:**
Debugging logs with AI assistants was painful - you'd have to copy/paste chunks, lose context, and manually format output. This lets Claude read your logs directly and give targeted insights.

**Tech stack:**
- Python 3.10+
- FastMCP (MCP SDK)
- Pydantic v2
- 280 tests, 81%+ coverage

**Install:**
```
uvx codesdevs-log-analyzer install
```

GitHub: https://github.com/Fato07/log-analyzer-mcp

Would love feedback! What log formats or features would you want to see added?
```

---

## Hacker News

### Title
```
Show HN: Log Analyzer MCP – AI-powered log analysis for Claude Code
```

### Body
```
Hi HN!

I built an MCP server that lets AI assistants analyze log files directly. Just published to the official MCP Registry.

Key features:
- Auto-detects 9+ formats (syslog, Apache, JSONL, Python, Java, Docker, K8s)
- Extracts errors, groups similar ones, captures stack traces
- Natural language queries ("what errors happened in the last hour?")
- Sensitive data detection (PII, API keys, passwords)
- Streams 1GB+ files without memory issues
- Multi-file correlation for distributed debugging

Example usage in Claude Code:
> "Analyze /var/log/nginx/error.log and tell me what's causing the 502 errors"

GitHub: https://github.com/Fato07/log-analyzer-mcp

Built with Python/FastMCP. 14 tools, 280 tests.

What log analysis features would be most useful for your workflow?
```

---

## LinkedIn

```
Excited to announce that log-analyzer-mcp is now live on the official MCP Registry!

It's an AI-powered log analysis tool that integrates directly with Claude Code and other MCP-compatible clients.

Key capabilities:
- Automatic format detection for 9+ log types
- Error extraction with stack trace grouping
- Natural language queries
- Sensitive data detection (PII, credentials)
- Enterprise-scale file handling (1GB+)
- Multi-file correlation for distributed systems

This was a fun project combining my interests in developer tooling and AI integration.

Check it out: https://github.com/Fato07/log-analyzer-mcp

#opensource #devtools #ai #python #mcp
```

---

## MCP Discord / Community

```
Hey everyone!

Just published **log-analyzer-mcp** to the registry - an AI-powered log analysis server.

**14 tools including:**
- `log_analyzer_parse` - Auto-detect format from 9+ types
- `log_analyzer_search` - Pattern search with context
- `log_analyzer_extract_errors` - Group similar errors
- `log_analyzer_ask` - Natural language queries
- `log_analyzer_scan_sensitive` - Detect PII/credentials
- `log_analyzer_multi` - Cross-file correlation

**Install:**
```
uvx codesdevs-log-analyzer install
```

GitHub: https://github.com/Fato07/log-analyzer-mcp

Feedback welcome! What features would make this more useful for your debugging workflow?
```
