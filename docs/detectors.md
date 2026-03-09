# Detectors

AgentSniff uses eight detection modules that run concurrently. Each produces signals with confidence levels that are fused into a single score per host.

| Detector | Method | Requires Root | Confidence |
|---|---|---|---|
| **DNS Monitor** | Passive DNS monitoring for LLM API domain queries | Yes* | High |
| **Port Scanner** | Async TCP scanning of agent-related ports | No | Low-Medium |
| **AgentPin Prober** | `.well-known/agent-identity.json` discovery | No | Confirmed |
| **MCP Detector** | JSON-RPC 2.0 / SSE probing for MCP servers | No | Confirmed |
| **Endpoint Prober** | HTTP probing for agent framework signatures | No | Medium-High |
| **TLS Fingerprint** | JA3 fingerprinting of agent HTTP clients | Yes* | High |
| **Traffic Analyzer** | Behavioral pattern analysis (burst detection, LLM call patterns) | Yes* | Medium-High |
| **SSE Detector** | Server-Sent Events pattern detection | Yes* | Medium |

\* Falls back to non-root alternatives automatically.

---

## DNS Monitor

Passively captures DNS queries on the network and matches against 60+ known LLM API domains including OpenAI, Anthropic, Google, Mistral, Groq, Together, Cohere, DeepSeek, and Chinese providers (DashScope, Moonshot, Zhipu, MiniMax, Baidu, ByteDance).

Also matches domain suffixes for Azure OpenAI (`*.openai.azure.com`), AWS Bedrock (`*.bedrock-runtime.amazonaws.com`), GCP Vertex (`*.aiplatform.googleapis.com`), and others.

**Fallback**: When raw sockets are unavailable, resolves the top 20 LLM API domains and cross-references their IPs against active connections in `/proc/net/tcp`.

## Port Scanner

Async TCP scanner targeting 24+ ports associated with:

- **MCP servers**: 3000, 3001, 8080
- **Agent frameworks**: 8000 (FastAPI/vLLM), 8001, 5000 (Flask), 8888 (Jupyter)
- **LLM inference**: 11434 (Ollama), 1234 (LM Studio), 4000 (LiteLLM)
- **Vector databases**: 6333 (Qdrant), 8090 (Weaviate), 19530 (Milvus)
- **Agent platforms**: 3100 (Dify), 3080 (LibreChat), 8501 (Streamlit)
- **IDE agents**: 65432 (Continue.dev), 8443 (code-server), 2024 (LangGraph Studio)

Includes banner grabbing for service identification and self-corroboration.

## AgentPin Prober

Probes hosts for [AgentPin](https://agentpin.org) discovery documents at `/.well-known/agent-identity.json`. Valid AgentPin identities provide **confirmed** detection with full cryptographic provenance including issuer, capabilities, delegation chains, and revocation status.

Follows the AgentPin spec's no-redirect security policy. Probes HTTPS and HTTP across common ports (443, 8443, 8080, 3000, 8000, 80).

## MCP Detector

Probes for [Model Context Protocol](https://modelcontextprotocol.io) servers by sending JSON-RPC 2.0 `initialize` requests and checking for SSE endpoints. On confirmed servers, enumerates available tools, resources, and prompts.

Detects both HTTP+SSE and direct JSON-RPC transports.

## Endpoint Prober

Probes HTTP endpoints for signatures of 58+ agent frameworks. Pre-filters closed ports with a quick TCP connect check before firing HTTP probes.

For each reachable port, checks:

- **Framework-specific endpoints** (e.g., `/crew/status` for CrewAI, `/runs` for LangGraph)
- **Framework-identifying response headers** (e.g., `x-langchain-*`, `semantic-kernel-version`)
- **Agent metadata documents** (`/.well-known/agents.json`, `/AGENTS.md`, `/SKILL.md`)
- **OpenAPI specs** with AI-related content (`/openapi.json`, `/docs`)

Detected frameworks include: LangChain, CrewAI, AutoGen, Dify, Flowise, n8n, PydanticAI, LangGraph, AG2, Haystack, Composio, Letta, Mastra, and many more. Also detects IDE agents (Cursor, Copilot, Windsurf, Claude Code) via user-agent matching.

## TLS Fingerprint

Computes JA3 hashes from TLS ClientHello messages to identify agent HTTP client libraries (Python requests, httpx, aiohttp, Node.js fetch, Rust reqwest).

**Fallback**: Active TLS server probing on agent-associated ports when passive capture isn't available.

## Traffic Analyzer

Profiles network hosts by behavioral patterns characteristic of AI agents:

- **Burst detection** — Bursty tool invocation sequences
- **ORA loop** — Observe-reason-act timing patterns (tool call interspersed with LLM API call)
- **API diversity** — Connections to many different API targets
- **LLM API connections** — Active TCP connections to known LLM API IPs

Also analyzes `/proc/net/tcp` for established connections to known LLM API IP addresses.

## SSE Detector

Detects Server-Sent Events (SSE) streaming patterns characteristic of LLM responses. Looks for long-lived HTTP connections with `text/event-stream` content from known LLM API IPs.

**Requires**: Raw socket access for passive capture. No fallback.

---

## Selecting Detectors

Run specific detectors only:

```bash
agentsniff scan 192.168.1.0/24 --detectors port_scanner,endpoint_prober,mcp_detector
```

Available detector names: `dns_monitor`, `port_scanner`, `agentpin_prober`, `mcp_detector`, `endpoint_prober`, `tls_fingerprint`, `traffic_analyzer`, `sse_detector`.
