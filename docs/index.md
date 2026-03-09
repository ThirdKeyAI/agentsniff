# AgentSniff

**AI Agent Network Scanner** — Detect AI agents operating on your network through passive monitoring, active probing, protocol detection, and behavioral analysis.

---

## What AgentSniff Does

AgentSniff identifies AI agents on enterprise networks using eight complementary detection modules. It combines passive network observation with active probing to find agents built with LangChain, CrewAI, AutoGen, Symbiont, and 50+ other frameworks.

- **Passive monitoring** — DNS queries, TLS fingerprints, traffic patterns
- **Active probing** — Port scanning, endpoint probing, MCP detection, AgentPin discovery
- **Signal correlation** — Noisy-OR probability fusion across all detectors
- **Alerting** — Webhook and email notifications on detection
- **Dashboard** — Real-time web UI with SSE streaming

## Quick Start

```bash
# Install
pip install agentsniff

# Scan your network
agentsniff scan 192.168.1.0/24

# JSON output
agentsniff scan 10.0.0.0/24 --format json --output results.json

# Continuous monitoring with webhook alerts
agentsniff scan 192.168.1.0/24 --continuous 60 --webhook-url https://hooks.example.com

# Web dashboard
agentsniff serve --port 9090
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](getting-started.md) | Install, first scan, dashboard setup |
| [Detectors](detectors.md) | All eight detection modules explained |
| [CLI Reference](cli-reference.md) | Complete command-line usage |
| [Dashboard](dashboard.md) | Web dashboard and SSE streaming |
| [Configuration](configuration.md) | YAML, env vars, and runtime config |
| [Alerting](alerting.md) | Webhook, email, and cron-based alerts |
| [Integrations](integrations.md) | Optional Zeek and nmap integration |
| [API Reference](api-reference.md) | REST API endpoints |
| [Architecture](architecture.md) | Internals, signal correlation, confidence scoring |
| [Wazuh Integration](wazuh.md) | SIEM rules for AgentSniff logs |

## Links

- [GitHub](https://github.com/ThirdKeyAI/agentsniff)
- [Website](https://agentsniff.org)
- [PyPI](https://pypi.org/project/agentsniff/)
