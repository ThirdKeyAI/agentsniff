# Detectors

AgentSniff uses nine detection modules that run concurrently. Each produces signals with confidence levels that are fused into a single score per host.

| Detector | Method | Requires Root | Confidence |
|---|---|---|---|
| **DNS Monitor** | Passive DNS monitoring for LLM API domain queries | Yes* | High |
| **Port Scanner** | Async TCP scanning of agent-related ports | No | Low-Medium |
| **AgentPin Prober** | `.well-known/agent-identity.json` discovery | No | Medium (unsigned) |
| **A2A Detector** | Agent Card discovery and trusted JWS verification | No | High-Confirmed |
| **MCP Detector** | Version-negotiated JSON-RPC / SSE probing for MCP servers | No | High-Confirmed |
| **Endpoint Prober** | HTTP probing for agent framework signatures | No | Medium-High |
| **TLS Fingerprint** | JA3/JA4 client-library hints with capture provenance | Yes* | Low |
| **Traffic Analyzer** | Behavioral pattern analysis (burst detection, LLM call patterns) | Yes* | Medium-High |
| **SSE Detector** | Server-Sent Events pattern detection | Yes* | Medium |

\* Falls back to non-root alternatives automatically.

The four detectors marked "Requires Root" can use kernel-level eBPF capture when the binary is built with `--features ebpf` and run with the necessary capabilities. Without eBPF, the detectors use userspace fallback paths where available.

---

## DNS Monitor

Passively captures DNS queries on the network and matches against 110+ known LLM API domains including OpenAI, Anthropic, Google, Mistral, Groq, Together, Cohere, DeepSeek, xAI, and Chinese providers (DashScope, Moonshot, Zhipu, MiniMax, Baidu, ByteDance, Tencent Hunyuan).

Also matches label-safe patterns for Azure Foundry (`*.services.ai.azure.com`), AWS Bedrock and AgentCore, GCP Vertex (`*.aiplatform.googleapis.com`), and others. Wildcards match exactly one DNS label.

Additionally tracks 150+ agent infrastructure domains — skill registries (ClawHub, Smithery, Glama), agent observability platforms (Langfuse, LangSmith, Helicone), tool connectivity services (Composio, Moltyverse), AI coding-agent backends (Cursor, Devin, Zed, Cline, Warp), and vendor-hosted remote MCP servers (GitHub, Slack, Figma, Notion, Linear, Stripe, Datadog).

**Fallback**: When raw sockets are unavailable, resolves the top 20 LLM API domains and cross-references their IPs against active connections in `/proc/net/tcp`.

## Port Scanner

Async TCP scanner targeting 24+ ports associated with:

- **MCP servers**: 3000, 3001, 6274, 8080
- **Agent frameworks**: 8000 (FastAPI/vLLM), 8001, 5000 (Flask), 8888 (Jupyter)
- **LLM inference**: 11434 (Ollama), 1234 (LM Studio), 4000 (LiteLLM), 30000 (SGLang)
- **Vector databases**: 6333 (Qdrant), 50051 (Weaviate gRPC), 19530 (Milvus)
- **Agent platforms**: 3100 (Dify), 3080 (LibreChat), 8501 (Streamlit)
- **IDE agents**: 65432 (Continue.dev), 8443 (code-server), 2024 (LangGraph Studio)

The signed catalog can assign multiple candidates to ambiguous ports such as 8080. Port-only matches remain low confidence; a banner, protocol response, or another detector must corroborate them.

## AgentPin Prober

Probes hosts for [AgentPin](https://agentpin.org) discovery documents at `/.well-known/agent-identity.json`. The current implementation validates the AgentPin v0.1 document shape, including entity metadata, P-256 public-key declarations, delegation depth, timestamp, and agent declarations. It does not verify credentials, domain ownership, delegation, expiry, or revocation state, so it reports an explicit **unsigned, medium-confidence discovery** rather than a verified identity. The optional v0.3 `a2a_endpoint` is retained as cross-protocol evidence.

Follows the AgentPin spec's no-redirect security policy. Probes HTTPS and HTTP across common ports (443, 8443, 8080, 3000, 8000, 80).

AgentPin itself is a discovery and identity layer rather than an MCP server. The MCP detector recognizes servers that advertise the AgentPin credential-binding capability and reports `mcp_agentpin_binding_advertised` at high confidence. This means the server claims support for carrying AgentPin credentials in MCP metadata; it does **not** mean a credential was presented or an identity was cryptographically verified.

## A2A Detector

Fetches the permanent `/.well-known/agent-card.json` discovery resource and validates the required Agent Card fields. The legacy `/.well-known/agent.json` path is accepted as compatibility evidence and identified as such.

Unsigned cards and cards with unknown signers report A2A presence without claiming verified identity. A card reaches `CONFIRMED` only when an ES256 JWS verifies against an out-of-band public key configured in `a2a_trusted_keys`. Keys advertised by the scanned host are never trust anchors.

## MCP Detector

Probes for [Model Context Protocol](https://modelcontextprotocol.io) servers using the signed protocol catalog. It tries `2026-07-28` `server/discover` first, then compatible `initialize` probes for `2025-11-25` and `2024-11-05`. Requests carry `MCP-Protocol-Version` and `Mcp-Method`; legacy session identifiers and the initialized notification are preserved when required. On confirmed servers, it enumerates available tools, resources, and prompts.

Detects both HTTP+SSE and direct JSON-RPC transports.

## Endpoint Prober

Probes HTTP endpoints for signatures of 100+ agent frameworks. Pre-filters closed ports with a quick TCP connect check before firing HTTP probes.

For each reachable port, checks:

- **Framework-specific and well-known paths** (e.g., `/crew/status` for CrewAI, `/runs` for LangGraph)
- **Framework-identifying response headers** (e.g., `x-langchain-*`, `semantic-kernel-version`)
- **Response body markers and JSON predicates** from the signed schema
- **Agent metadata documents** (`/.well-known/agents.json`, `/AGENTS.md`, `/SKILL.md`)
- **OpenAPI specs** with AI-related content (`/openapi.json`, `/docs`)

Detected frameworks include: LangChain, CrewAI, AutoGen, Dify, Flowise, n8n, PydanticAI, LangGraph, AG2, Haystack, Composio, Letta, Mastra, and many more. Request User-Agent and MCP client-name indicators are kept as passive indicators and are never searched in server response bodies.

## TLS Fingerprint

Computes JA3 and JA4 fingerprints from TLS ClientHello messages to produce low-confidence client-library hints. Each catalog entry records library versions, TLS backend, capture time, and source; legacy entries are explicitly marked for recapture. These generic fingerprints never establish agent identity.

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

**Requires**: Raw socket access (or eBPF with `--features ebpf`) for passive capture.

---

## Selecting Detectors

Run specific detectors only:

```bash
agentsniff scan 192.168.1.0/24 --detectors port_scanner,endpoint_prober,mcp_detector
```

Available detector names: `dns_monitor`, `port_scanner`, `agentpin_prober`, `a2a_detector`, `mcp_detector`, `endpoint_prober`, `tls_fingerprint`, `traffic_analyzer`, `sse_detector`.
