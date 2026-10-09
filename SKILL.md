# AgentSniff

Rust-based AI-agent network scanner for authorized environments.

## Use

```bash
cargo install agentsniff --locked
agentsniff scan 192.168.1.0/24
agentsniff serve --port 9090
```

The server binds to `127.0.0.1` by default. Loopback use is credential-free; non-loopback binding requires a 32-byte-or-longer `AGENTSNIFF_API_TOKEN`, which protects every non-health route with Basic/Bearer authentication. Use TLS for remote access.

## Detectors

| Detector | Evidence |
|---|---|
| `dns_monitor` | LLM and agent-infrastructure DNS activity |
| `port_scanner` | Agent, MCP, inference, and vector-service ports |
| `agentpin_prober` | Unsigned AgentPin discovery documents |
| `mcp_detector` | MCP JSON-RPC and SSE behavior |
| `endpoint_prober` | Framework endpoints, headers, and metadata |
| `tls_fingerprint` | TLS client fingerprints |
| `traffic_analyzer` | Agent-like traffic patterns |
| `sse_detector` | Long-lived event-stream traffic |

AgentPin metadata is not cryptographically verified by the current implementation and is deliberately reported as unverified discovery evidence.

## API

Start scans with JSON:

```bash
curl --request POST http://127.0.0.1:9090/api/scan \
  --header 'Content-Type: application/json' \
  --data '{"network":"192.168.1.0/24"}'
```

Subscribe to `GET /api/scan/stream` for read-only SSE events.
