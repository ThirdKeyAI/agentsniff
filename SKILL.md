# AgentSniff

AI Agent Network Scanner — Detect AI agents operating on your network.

## What It Does

AgentSniff identifies AI agents on enterprise networks through:
- **Passive monitoring**: DNS queries to LLM APIs, TLS fingerprinting, traffic behavioral analysis
- **Active probing**: Port scanning, AgentPin identity discovery, MCP server detection, HTTP endpoint fingerprinting
- **Signal fusion**: Combines evidence from multiple detectors using noisy-OR probability scoring

## Quick Start

```bash
# Install
pip install agentsniff

# Scan a network
agentsniff scan 192.168.1.0/24

# Start web dashboard
agentsniff serve --port 9090

# Continuous monitoring with alerts
agentsniff scan 192.168.1.0/24 --continuous 300 --webhook-url https://hooks.example.com/alert
```

## Detectors

| Detector | What It Finds |
|---|---|
| `dns_monitor` | Hosts querying LLM API domains (OpenAI, Anthropic, etc.) |
| `port_scanner` | Open ports for MCP servers, Ollama, vector DBs, agent platforms |
| `agentpin_prober` | AgentPin identity documents at `.well-known/agent-identity.json` |
| `mcp_detector` | Model Context Protocol servers (JSON-RPC + SSE) |
| `endpoint_prober` | Agent framework signatures (LangChain, CrewAI, AutoGen, Dify, n8n, etc.) |
| `tls_fingerprint` | JA3/JA4+ fingerprints matching known agent HTTP clients |
| `traffic_analyzer` | ORA-loop behavioral patterns and active LLM API connections |
| `sse_detector` | LLM streaming response patterns |

## API

REST API available when running `agentsniff serve`:

- `POST /api/scan?network=CIDR` — Start a scan
- `GET /api/scan/stream?network=CIDR` — SSE real-time scan
- `GET /api/scan/status` — Current scan state
- `GET /api/scan/results` — Latest results
- `GET /api/scan/history` — Historical scans
- `POST /api/scan/stop` — Cancel running scan
- `GET /api/agents` — All detected agents
- `GET /api/scan/sarif` — Export as SARIF

## Output Formats

`--format table` (default), `json`, `csv`, `sarif`

## Configuration

```bash
agentsniff init-config  # generates agentsniff.yaml
```

Environment variables: `AGENTSNIFF_TARGET_NETWORK`, `AGENTSNIFF_ENABLE_DNS_MONITOR`, etc.

## Requirements

- Python 3.11+
- Linux recommended
- Root/CAP_NET_RAW optional (enables passive detectors)

## Links

- [PyPI](https://pypi.org/project/agentsniff/)
- [GitHub](https://github.com/ThirdKeyAI/agentsniff)
- [AgentPin](https://agentpin.org) | [SchemaPin](https://schemapin.org) | [Symbiont](https://symbiont.dev)
