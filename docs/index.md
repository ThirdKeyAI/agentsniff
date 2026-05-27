# AgentSniff

**AI Agent Network Scanner** — Detect AI agents operating on your network through passive monitoring, active probing, protocol detection, and behavioral analysis.

---

## What AgentSniff Does

AgentSniff identifies AI agents on enterprise networks using eight complementary detection modules. It combines passive network observation with active probing to find agents built with LangChain, CrewAI, AutoGen, Symbiont, and 100+ other frameworks.

- **Passive monitoring** — DNS queries, TLS fingerprints, traffic patterns
- **Active probing** — Port scanning, endpoint probing, MCP detection, AgentPin discovery
- **Signal correlation** — Noisy-OR probability fusion across all detectors
- **Alerting** — Webhook and email notifications on detection
- **Dashboard** — Real-time web UI with SSE streaming

## Implementations

AgentSniff ships in two source trees on `main`, sharing the same CLI surface, dashboard, REST API, signed signature files, and on-disk schema:

| Version | Source | Status |
|---|---|---|
| **v2 (Rust)** | `agentsniff-rs/` | Current stable — adds eBPF passive capture, PostgreSQL / Redis storage backends, and Zeek / Nmap integrations |
| **v1 (Python)** | `agentsniff/` | Legacy — still maintained for parity, but new work targets v2 |

Everything in this documentation set applies to both versions unless explicitly tagged "v1 only" or "v2 only".

## Quick Start

```bash
# v2 (Rust — recommended). Pick any one of:
curl -fsSL https://agentsniff.org/install.sh | bash
cargo install agentsniff
# or download a signed pre-built archive from:
#   https://github.com/ThirdKeyAI/agentsniff/releases/latest

agentsniff scan 192.168.1.0/24

# v1 (Python)
pip install agentsniff
agentsniff scan 192.168.1.0/24

# Same flags on both versions
agentsniff scan 10.0.0.0/24 --format json --output results.json
agentsniff scan 192.168.1.0/24 --continuous 60 --webhook-url https://hooks.example.com
agentsniff serve --port 9090
```

Pre-built binaries are available for Linux x86_64 / aarch64, macOS Apple Silicon / Intel, and Windows x86_64 — every archive is signed with [Sigstore cosign](https://docs.sigstore.dev/). See [Getting Started](getting-started.md) for verification commands.

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
- [crates.io](https://crates.io/crates/agentsniff)
- [PyPI](https://pypi.org/project/agentsniff/)
