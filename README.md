# AgentSniff

**AI Agent Network Scanner** — Detect AI agents operating on your network through passive monitoring, active probing, protocol detection, and behavioral analysis.

## Overview

AgentSniff identifies AI agents on enterprise networks using seven complementary detection modules:

| Detector | Method | Requires Root | Confidence |
|---|---|---|---|
| **DNS Monitor** | Passive DNS monitoring for LLM API domain queries | Yes* | High |
| **Port Scanner** | Async TCP scanning of agent-related ports | No | Low–Medium |
| **AgentPin Prober** | `.well-known/agent-identity.json` discovery | No | Confirmed |
| **MCP Detector** | JSON-RPC 2.0 / SSE probing for MCP servers | No | Confirmed |
| **Endpoint Prober** | HTTP probing for agent framework signatures | No | Medium–High |
| **TLS Fingerprint** | JA3 fingerprinting of agent HTTP clients | Yes* | High |
| **Traffic Analyzer** | Behavioral pattern analysis (burst detection, LLM call patterns) | Yes* | Medium–High |

\* Falls back to non-root alternatives automatically.

## Quick Start

### Standalone

```bash
# Install
pip install -e .

# Scan your local network
agentsniff scan 192.168.1.0/24

# Scan specific hosts
agentsniff scan --hosts server1,server2,server3

# JSON output
agentsniff scan 10.0.0.0/24 --format json --output results.json

# Continuous monitoring (every 60 seconds)
agentsniff scan 192.168.1.0/24 --continuous 60

# Start web dashboard
agentsniff serve --port 9090
```

### Docker

```bash
# Build
docker build -t agentsniff .

# Run web dashboard (host network for full visibility)
docker run -d --name agentsniff \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  agentsniff

# Run one-shot scan
docker run --rm --network host --cap-add NET_RAW \
  agentsniff scan 192.168.1.0/24

# Docker Compose
docker compose up -d
```

### Docker Compose

```bash
docker compose up -d
# Dashboard at http://localhost:9090
```

## CLI Usage

```
agentsniff <command> [options]

Commands:
  scan          Run a network scan
  serve         Start web dashboard API server
  init-config   Generate default configuration file

Scan Options:
  network              Target network CIDR (default: 192.168.1.0/24)
  --hosts HOST,HOST    Specific hosts to scan
  --exclude HOST,HOST  Hosts to exclude
  --config FILE        YAML configuration file
  --format FORMAT      Output: table, json, csv (default: table)
  --output FILE        Save results to file
  --detectors D,D      Enable specific detectors only
  --timeout SECS       HTTP timeout (default: 5.0)
  --concurrency N      Max concurrent connections (default: 100)
  --continuous SECS    Repeat scan every N seconds
  --webhook-url URL    Webhook URL for alerts (auto-enables alerting)
  --smtp-to ADDR,ADDR  Email recipients for alerts (auto-enables alerting)
  --db PATH            SQLite database path (default: ~/.agentsniff/agentsniff.db)
  --log-file PATH      Log file path (default: no file logging)
  -v, --verbose        Debug logging
  -q, --quiet          Minimal output

Serve Options:
  --host ADDR          Bind address (default: 0.0.0.0)
  --port PORT          Bind port (default: 9090)
  --network CIDR       Default scan target
  --db PATH            SQLite database path (default: ~/.agentsniff/agentsniff.db)
  --log-file PATH      Log file path (default: no file logging)
```

## Detection Details

### DNS Monitor
Passively captures DNS queries on the network and matches against 40+ known LLM API domains (OpenAI, Anthropic, Google, Mistral, Groq, Together, Cohere, etc.) plus Azure/AWS/GCP suffixes. Falls back to active DNS resolution cross-referencing if raw sockets are unavailable.

### Port Scanner
Async TCP scanner targeting ports associated with MCP servers (3000, 3001, 8080), LLM inference engines (11434/Ollama, 1234/LM Studio), vector databases (6333/Qdrant, 8090/Weaviate, 19530/Milvus), and agent platforms (3080/LibreChat, 8501/Streamlit). Includes banner grabbing for service identification.

### AgentPin Prober
Probes hosts for <a href="https://agentpin.org" target="_blank">AgentPin</a> discovery documents at `/.well-known/agent-identity.json`. Valid AgentPin identities provide **confirmed** detection with full cryptographic provenance including issuer, capabilities, delegation chains, and revocation status. Follows the AgentPin spec's no-redirect security policy.

### MCP Detector
Actively probes for <a href="https://modelcontextprotocol.io" target="_blank">Model Context Protocol</a> servers by sending JSON-RPC 2.0 `initialize` requests and checking for SSE endpoints. On confirmed servers, enumerates available tools, resources, and prompts. Detects both HTTP+SSE and direct JSON-RPC transports.

### Endpoint Prober
Probes HTTP endpoints for signatures of known agent frameworks: LangChain/LangServe, CrewAI, AutoGen, Symbiont, Dify, Flowise, n8n. Checks health endpoints, OpenAPI specs, and framework-specific paths. Analyzes response headers for agent framework fingerprints.

### TLS Fingerprint
Computes JA3 hashes from TLS ClientHello messages to identify agent HTTP client libraries (Python requests, httpx, aiohttp, Node.js fetch, Rust reqwest). Falls back to active TLS server probing on agent-associated ports when passive capture isn't available.

### Traffic Analyzer
Profiles network hosts by behavioral patterns characteristic of AI agents: bursty tool invocation sequences interspersed with LLM API calls (the observe-reason-act loop), streaming SSE connections, and diverse API target sets. Also analyzes `/proc/net/tcp` for established connections to known LLM API IP addresses.

## Storage

AgentSniff persists scan history to a local SQLite database. By default the database is at `~/.agentsniff/agentsniff.db` and is created automatically on first use.

```bash
# Use default database location
agentsniff scan 192.168.1.0/24

# Custom database path
agentsniff scan 192.168.1.0/24 --db /var/lib/agentsniff/scans.db

# Enable file logging alongside console output
agentsniff scan 192.168.1.0/24 --log-file /var/log/agentsniff/scan.log

# Both flags also work with the serve command
agentsniff serve --db /var/lib/agentsniff/scans.db --log-file /var/log/agentsniff/server.log
```

Storage can also be configured in `agentsniff.yaml`:

```yaml
db_path: ""       # default: ~/.agentsniff/agentsniff.db
log_file: ""      # empty = console only
```

Or via environment variables:

```bash
export AGENTSNIFF_DB_PATH="/var/lib/agentsniff/scans.db"
export AGENTSNIFF_LOG_FILE="/var/log/agentsniff/scan.log"
```

The database stores full scan results including detected agents and signals. The web dashboard's Scan History panel loads from the database, so history persists across server restarts.

## Configuration

Generate a default config file:

```bash
agentsniff init-config
# Creates agentsniff.yaml
```

Configuration can also be set via environment variables with the `AGENTSNIFF_` prefix:

```bash
export AGENTSNIFF_TARGET_NETWORK="10.0.0.0/16"
export AGENTSNIFF_ENABLE_DNS_MONITOR=true
export AGENTSNIFF_HTTP_TIMEOUT=10.0
```

## Alerting

AgentSniff can send alerts when agents are detected during scans. Configure via YAML, environment variables, CLI flags, or the dashboard settings modal.

### Webhook

```bash
# CLI — auto-enables alerting
agentsniff scan 192.168.1.0/24 --webhook-url https://hooks.example.com/agentsniff

# Continuous monitoring with webhook
agentsniff scan 192.168.1.0/24 --continuous 300 --webhook-url https://hooks.example.com/agentsniff
```

Webhook payload (POST JSON):

```json
{
  "source": "agentsniff",
  "timestamp": "2026-03-02T12:00:00Z",
  "scan_id": "scan-20260302-120000",
  "target_network": "192.168.1.0/24",
  "total_agents": 3,
  "by_confidence": {"confirmed": 1, "high": 1, "medium": 1},
  "agents": [...]
}
```

### Email (SMTP)

```yaml
# In agentsniff.yaml
alert_enabled: true
alert_min_agents: 1
alert_min_confidence: medium
alert_cooldown: 600  # no more than one alert per 10 minutes

smtp_host: "smtp.example.com"
smtp_port: 587
smtp_user: "alerts@example.com"
smtp_password: "your-password"
smtp_use_tls: true
smtp_from: "agentsniff@example.com"
smtp_to:
  - "admin@example.com"
  - "security@example.com"
```

### Cron Job Example

Run periodic scans from cron with webhook alerts and archived JSON output:

```bash
# Scan every 10 minutes, alert via webhook, save results
*/10 * * * * agentsniff scan 192.168.1.0/24 --webhook-url https://hooks.example.com/agentsniff --format json --output /var/log/agentsniff/scan-$(date +\%Y\%m\%d-\%H\%M).json 2>&1 | logger -t agentsniff
```

### Dashboard Settings

When running the web dashboard (`agentsniff serve`), click the ⚙ gear icon to configure alert settings interactively — including webhook URL, SMTP credentials, thresholds, and a Test Alert button.

## API Endpoints

When running `agentsniff serve`:

| Endpoint | Method | Description |
|---|---|---|
| `GET /` | — | Web dashboard |
| `GET /docs` | — | Swagger / OpenAPI docs |
| `GET /api/health` | — | Health check |
| `POST /api/scan` | `?network=CIDR` | Start a scan |
| `GET /api/scan/status` | — | Current scan status |
| `GET /api/scan/results` | — | Latest scan results |
| `GET /api/scan/history` | `?limit=&offset=` | Previous scan results (from DB) |
| `GET /api/scan/{scan_id}` | — | Get a specific historical scan |
| `GET /api/agents` | — | All detected agents |
| `GET /api/scan/stream` | SSE | Real-time scan streaming |
| `GET /api/settings` | — | Get alert settings |
| `PUT /api/settings` | JSON body | Update alert settings |
| `POST /api/settings/test` | — | Send test alert |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                 AgentSniff CLI                   │
│         agentsniff scan | serve                  │
├──────────┬───────────────────────┬───────────────┤
│ REST API │    Scanner Engine     │  Web Dashboard│
│ (FastAPI)│                       │  (HTML/JS/CSS)│
├──────────┴───────────┬───────────┴───────────────┤
│              Signal Correlator                   │
│     Groups signals by host, calculates scores    │
├─────┬─────┬─────┬─────┬─────┬─────┬──────────────┤
│ DNS │Port │Agent│ MCP │ EP  │ TLS │  Traffic     │
│ Mon │Scan │Pin  │ Det │Probe│ FP  │  Analyzer    │
├─────┴─────┴─────┴─────┴─────┴─────┴──────────────┤
│              Target Network                      │
└──────────────────────────────────────────────────┘
```

Signals from all detectors are correlated using noisy-OR probability combination, grouping by source host IP to produce unified `DetectedAgent` records with aggregate confidence scores.

## Integration with ThirdKey Trust Stack

AgentSniff complements the ThirdKey trust infrastructure:

- <a href="https://agentpin.org/" target="_blank"><strong>AgentPin</strong></a> — Cooperative agent discovery via cryptographic identity documents
- <a href="https://schemapin.org/" target="_blank"><strong>SchemaPin</strong></a> — Verified tools detected on MCP servers can be cross-checked against SchemaPin signatures
- <a href="https://symbiont.dev/" target="_blank"><strong>Symbiont</strong></a> — AgentSniff can run as a Symbiont agent with policy-enforced scanning boundaries
- <a href="https://github.com/ThirdKeyAI/AgentNull" target="_blank"><strong>AgentNull</strong></a> — Detection evasion research feeds back into scanner improvements

## Requirements

- Python 3.11+
- Linux recommended (for `/proc/net/tcp` analysis)
- Root/CAP_NET_RAW optional (enables passive DNS, TLS, and traffic monitoring)

## License

Apache License 2.0 — Jascha Wanger / ThirdKey AI

## Disclaimer

AgentSniff is intended for authorized network scanning and security assessment only. You must only scan networks and systems that you own or have explicit written permission to test. Unauthorized scanning of networks may violate applicable laws and regulations, including the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and similar legislation in other jurisdictions. The authors and contributors are not responsible for any misuse of this tool or any damages resulting from its use. By using AgentSniff, you agree to use it in compliance with all applicable laws and only against targets you are authorized to scan.
