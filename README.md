# AgentScan

**AI Agent Network Scanner** — Detect AI agents operating on your network through passive monitoring, active probing, protocol detection, and behavioral analysis.

## Overview

AgentScan identifies AI agents on enterprise networks using seven complementary detection modules:

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
agentscan scan 192.168.1.0/24

# Scan specific hosts
agentscan scan --hosts server1,server2,server3

# JSON output
agentscan scan 10.0.0.0/24 --format json --output results.json

# Continuous monitoring (every 60 seconds)
agentscan scan 192.168.1.0/24 --continuous 60

# Start web dashboard
agentscan serve --port 9090
```

### Docker

```bash
# Build
docker build -t agentscan .

# Run web dashboard (host network for full visibility)
docker run -d --name agentscan \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  agentscan

# Run one-shot scan
docker run --rm --network host --cap-add NET_RAW \
  agentscan scan 192.168.1.0/24

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
agentscan <command> [options]

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
  -v, --verbose        Debug logging
  -q, --quiet          Minimal output

Serve Options:
  --host ADDR          Bind address (default: 0.0.0.0)
  --port PORT          Bind port (default: 9090)
  --network CIDR       Default scan target
```

## Detection Details

### DNS Monitor
Passively captures DNS queries on the network and matches against 40+ known LLM API domains (OpenAI, Anthropic, Google, Mistral, Groq, Together, Cohere, etc.) plus Azure/AWS/GCP suffixes. Falls back to active DNS resolution cross-referencing if raw sockets are unavailable.

### Port Scanner
Async TCP scanner targeting ports associated with MCP servers (3000, 3001, 8080), LLM inference engines (11434/Ollama, 1234/LM Studio), vector databases (6333/Qdrant, 8090/Weaviate, 19530/Milvus), and agent platforms (3080/LibreChat, 8501/Streamlit). Includes banner grabbing for service identification.

### AgentPin Prober
Probes hosts for [AgentPin](https://agentpin.org) discovery documents at `/.well-known/agent-identity.json`. Valid AgentPin identities provide **confirmed** detection with full cryptographic provenance including issuer, capabilities, delegation chains, and revocation status. Follows the AgentPin spec's no-redirect security policy.

### MCP Detector
Actively probes for [Model Context Protocol](https://modelcontextprotocol.io) servers by sending JSON-RPC 2.0 `initialize` requests and checking for SSE endpoints. On confirmed servers, enumerates available tools, resources, and prompts. Detects both HTTP+SSE and direct JSON-RPC transports.

### Endpoint Prober
Probes HTTP endpoints for signatures of known agent frameworks: LangChain/LangServe, CrewAI, AutoGen, Symbiont, Dify, Flowise, n8n. Checks health endpoints, OpenAPI specs, and framework-specific paths. Analyzes response headers for agent framework fingerprints.

### TLS Fingerprint
Computes JA3 hashes from TLS ClientHello messages to identify agent HTTP client libraries (Python requests, httpx, aiohttp, Node.js fetch, Rust reqwest). Falls back to active TLS server probing on agent-associated ports when passive capture isn't available.

### Traffic Analyzer
Profiles network hosts by behavioral patterns characteristic of AI agents: bursty tool invocation sequences interspersed with LLM API calls (the observe-reason-act loop), streaming SSE connections, and diverse API target sets. Also analyzes `/proc/net/tcp` for established connections to known LLM API IP addresses.

## Configuration

Generate a default config file:

```bash
agentscan init-config
# Creates agentscan.yaml
```

Configuration can also be set via environment variables with the `AGENTSCAN_` prefix:

```bash
export AGENTSCAN_TARGET_NETWORK="10.0.0.0/16"
export AGENTSCAN_ENABLE_DNS_MONITOR=true
export AGENTSCAN_HTTP_TIMEOUT=10.0
```

## API Endpoints

When running `agentscan serve`:

| Endpoint | Method | Description |
|---|---|---|
| `GET /` | — | Web dashboard |
| `GET /api/health` | — | Health check |
| `POST /api/scan` | `?network=CIDR` | Start a scan |
| `GET /api/scan/status` | — | Current scan status |
| `GET /api/scan/results` | — | Latest scan results |
| `GET /api/scan/history` | — | Previous scan results |
| `GET /api/agents` | — | All detected agents |
| `GET /api/scan/stream` | SSE | Real-time scan streaming |

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  AgentScan CLI                    │
│          agentscan scan | serve                   │
├──────────┬───────────────────────┬────────────────┤
│ REST API │    Scanner Engine     │  Web Dashboard  │
│ (FastAPI)│                       │  (HTML/JS/CSS)  │
├──────────┴───────────┬───────────┴────────────────┤
│              Signal Correlator                     │
│     Groups signals by host, calculates scores     │
├─────┬─────┬─────┬─────┬─────┬─────┬──────────────┤
│ DNS │Port │Agent│ MCP │ EP  │ TLS │  Traffic     │
│ Mon │Scan │Pin  │ Det │Probe│ FP  │  Analyzer   │
├─────┴─────┴─────┴─────┴─────┴─────┴──────────────┤
│              Target Network                        │
└──────────────────────────────────────────────────┘
```

Signals from all detectors are correlated using noisy-OR probability combination, grouping by source host IP to produce unified `DetectedAgent` records with aggregate confidence scores.

## Integration with ThirdKey Trust Stack

AgentScan complements the ThirdKey trust infrastructure:

- **AgentPin**: Cooperative agent discovery via cryptographic identity documents
- **SchemaPin**: Verified tools detected on MCP servers can be cross-checked against SchemaPin signatures
- **Symbiont**: AgentScan can run as a Symbiont agent with policy-enforced scanning boundaries
- **AgentNull**: Detection evasion research feeds back into scanner improvements

## Requirements

- Python 3.11+
- Linux recommended (for `/proc/net/tcp` analysis)
- Root/CAP_NET_RAW optional (enables passive DNS, TLS, and traffic monitoring)

## License

MIT License — ThirdKey AI
