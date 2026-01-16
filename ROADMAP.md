# Roadmap

## Current Version: 0.4.2

### What's Shipped
- 14 MCP tools for log analysis
- 9 log format parsers with auto-detection
- Published to official MCP Registry
- 280 tests, 81%+ coverage

---

## Phase 2: Extended Format Support (v0.5.0)

### New Log Formats
| Format | Priority | Description |
|--------|----------|-------------|
| AWS CloudWatch | P0 | CloudWatch Logs export format |
| Datadog | P1 | Datadog log format |
| Splunk | P1 | Splunk raw/JSON formats |
| ELK/Logstash | P1 | Elasticsearch, Logstash formats |
| Fluentd | P2 | Fluentd structured logs |
| Graylog GELF | P2 | Graylog Extended Log Format |

### New Features
- **`log_analyzer_stats`** - Statistical analysis (percentiles, histograms)
- **`log_analyzer_timeline`** - Visual timeline of events
- **`log_analyzer_export`** - Export filtered results to file

---

## Phase 3: Intelligence & ML (v0.6.0)

### Anomaly Detection
- Baseline learning from historical logs
- Spike detection (error rate, latency)
- Unusual pattern identification
- Time-series anomaly scoring

### Smart Alerts
- Define alert rules in natural language
- Threshold-based alerting
- Pattern-based alerting
- Correlation alerts (A happens then B)

### Root Cause Analysis
- Automated cause-effect chain building
- Dependency graph visualization
- Impact radius estimation

---

## Phase 4: Enterprise Features (v0.7.0)

### Scale
- Distributed log processing
- Index building for faster repeated queries
- Compressed log format support (.gz, .zst, .lz4)
- Log rotation handling

### Security
- Audit logging of tool usage
- Role-based access patterns
- Compliance report generation (SOC2, HIPAA)

### Integration
- Webhook notifications
- Slack/Teams integration
- PagerDuty integration
- Custom output formatters

---

## Phase 5: Interactive & Visual (v0.8.0)

### Interactive Mode
- Live log viewer with filtering
- Real-time search as you type
- Bookmark interesting entries
- Session history

### Visualization
- Error frequency charts
- Request latency heatmaps
- Service dependency graphs
- Log volume over time

---

## Content & Community

### Blog Posts
- [ ] "Building an MCP Server from Scratch"
- [ ] "AI-Powered Log Analysis: A Deep Dive"
- [ ] "Detecting Sensitive Data in Logs with ML"

### Videos
- [ ] Demo: Log analysis with Claude Code
- [ ] Tutorial: Building your first MCP server
- [ ] Deep dive: Architecture of log-analyzer-mcp

### Community
- [ ] GitHub Discussions enabled
- [ ] Discord channel for support
- [ ] Monthly community calls

---

## Contributing

Want to help? Pick an issue labeled `good first issue` or propose a new feature in Discussions.

Priority areas:
1. New log format parsers (easy to add, well-documented)
2. Test coverage improvements
3. Documentation and examples
4. Performance optimizations
