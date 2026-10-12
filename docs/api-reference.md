# API Reference

When running `agentsniff serve`, a REST API is available on `127.0.0.1:9090` by default. Loopback use is credential-free. Set a 32-byte-or-longer `AGENTSNIFF_API_TOKEN` to enable Basic/Bearer authentication; the server refuses non-loopback binding without one. `/api/health` remains public.

For API clients, send the token as a Bearer credential. Browsers can use HTTP Basic authentication with username `agentsniff` and the token as the password. Always use TLS when the listener is remotely reachable. Every state-changing request must use `Content-Type: application/json`, including endpoints whose body is `{}`; this also protects credential-free loopback deployments from cross-origin form posts.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `GET /` | — | Web dashboard |
| `GET /api/health` | — | Health check |
| `POST /api/scan` | JSON body | Start a scan |
| `POST /api/scan/stop` | JSON `{}` | Stop running scan |
| `GET /api/scan/status` | — | Current scan status |
| `GET /api/scan/results` | — | Latest scan results |
| `GET /api/scan/history` | `?limit=&offset=` | Previous scan results |
| `GET /api/scan/{scan_id}` | — | Specific historical scan |
| `GET /api/scan/sarif` | — | Latest scan as SARIF 2.1.0 JSON |
| `GET /api/agents` | — | All detected agents |
| `POST /api/agentpin/verify` | JSON body | Verify a presented AgentPin credential |
| `POST /mcp` | MCP JSON-RPC | AgentPin verification MCP server |
| `GET /api/scan/stream` | SSE | Real-time scan streaming |
| `GET /api/settings` | — | Get alert settings |
| `PUT /api/settings` | JSON body | Update alert settings |
| `POST /api/settings/test` | JSON `{}` | Send test alert |
| `GET /api/db/backup` | — | Download SQLite database snapshot |
| `POST /api/db/reset` | JSON `{}` | Wipe scan history |

Start a scan with an explicit JSON request:

```bash
curl --request POST http://127.0.0.1:9090/api/scan \
  --header "Authorization: Bearer ${AGENTSNIFF_API_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data '{"network":"192.168.1.0/24","detectors":"port_scanner,endpoint_prober"}'
```

## AgentPin verification API and MCP tool

Configure the server-side trust anchor, durable pins, and expected audience:

```yaml
agentpin_trust_bundle_path: "/etc/agentsniff/agentpin-trust-bundle.json"
agentpin_pin_store_path: "~/.agentsniff/agentpin-pins.json"
agentpin_expected_audience: "verifier.example"
```

The server refuses to start if this configuration is incomplete or unreadable.
The trust bundle must be distributed through an authenticated out-of-band
channel. A caller cannot submit a trust bundle or audience alongside its
credential.

REST clients send a JSON body to `POST /api/agentpin/verify`:

```json
{"credential":"eyJ...presented AgentPin JWT..."}
```

The endpoint returns the same machine-readable report as
`agentsniff verify-agentpin`. A rejected credential is a successful HTTP
exchange with `"valid": false`; configuration and storage failures return
`503`. Credentials are limited to 64 KiB, and the route uses the same
Basic/Bearer authentication policy as the rest of the management API.

MCP clients connect to `POST /mcp`. AgentSniff supports current stateless MCP
`2026-07-28` (`server/discover`, `tools/list`, and `tools/call`) and stateless
legacy initialization for `2025-11-25` clients. The exposed tool is:

```text
verify_agentpin_credential({credential: string})
```

Current-protocol HTTP clients must send matching `MCP-Protocol-Version`,
`Mcp-Method`, and, for `tools/call`, `Mcp-Name` headers. Verification results
are returned in both `structuredContent` and text content for compatibility.
The API token can be sent as an `Authorization: Bearer ...` header.

## SSE Streaming

The `/api/scan/stream` endpoint provides real-time scan updates via Server-Sent Events:

```
GET /api/scan/stream
```

### Event Types

The event tag is carried inside each JSON payload's `event` field (the SSE stream uses unnamed `message` events). Possible values:

| `event` value | Data | Description |
|-------|------|-------------|
| `scan_started` | `{scan_id, network, host_count, detectors}` | Scan has begun |
| `agent_detected` | `{agent: <DetectedAgent>}` | New agent found or updated |
| `scan_progress` | `{message}` | Free-form progress update |
| `scan_completed` | `{scan_id, agent_count, summary}` | Scan finished |
| `scan_cancelled` | `{scan_id, agent_count, summary}` | Partial scan stopped; never used as a baseline |
| `scan_error` | `{message}` | Scan failed |

### Example

```javascript
const source = new EventSource('/api/scan/stream');

await fetch('/api/scan', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({network: '192.168.1.0/24'})
});

source.onmessage = (e) => {
  const payload = JSON.parse(e.data);
  switch (payload.event) {
    case 'agent_detected':
      console.log(`Found: ${payload.agent.framework} at ${payload.agent.ip_address}:${payload.agent.port}`);
      break;
    case 'scan_completed':
      console.log(`Done: ${payload.agent_count} agents`);
      source.close();
      break;
  }
};
```

## Scan Result Schema

```json
{
  "scan_id": "a1b2c3d4",
  "scope_id": "scope-0123456789abcdef0123456789abcdef",
  "started_at": "ISO8601",
  "completed_at": "ISO8601",
  "target_network": "CIDR",
  "agents": [],
  "detectors_run": ["port_scanner", "endpoint_prober", "mcp_detector"],
  "errors": [],
  "diff": {
    "baseline_scan_id": "prior123",
    "new_assets": ["asset-0123"],
    "changed_assets": [],
    "unchanged_assets": ["asset-4567"],
    "removed_assets": []
  }
}
```

The completed SSE event and historical-scan response also include a summary with presence-confidence counts, trusted and invalid identity counts, and new/changed/removed totals.

## Agent Schema

```json
{
  "id": "asset-0123456789abcdef0123456789abcdef",
  "host": "hostname",
  "ip_address": "192.168.1.50",
  "port": 8000,
  "transport": "tcp",
  "agent_type": "framework",
  "framework": "langchain",
  "status": "detected",
  "presence_status": "confirmed",
  "identity_assurance": "unknown",
  "risk_level": "unknown",
  "change_status": "new",
  "confidence_score": 0.95,
  "confidence_level": "confirmed",
  "signal_count": 4,
  "signals": [...],
  "agentpin_identity": null,
  "mcp_capabilities": null,
  "tls_fingerprint": null,
  "first_seen": "ISO8601",
  "last_seen": "ISO8601",
  "metadata": {}
}
```

Asset IDs are deterministic for `(IP, port, transport)`; host-level passive observations omit the port. `presence_status` is `unknown`, `suspected`, `detected`, or `confirmed`. `identity_assurance` is independently `unknown`, `self_asserted`, `signed_untrusted`, `invalid`, or `trusted_verified`. The compatibility `status` value `verified` is emitted only for `trusted_verified` identity assurance. `change_status` is `new`, `changed`, `unchanged`, or `unclassified`.

## Detection Signal Schema

```json
{
  "detector": "endpoint_prober",
  "signal_type": "framework_endpoint_match",
  "description": "langchain endpoint active at http://192.168.1.50:8000/docs",
  "confidence": "high",
  "evidence": {
    "host": "192.168.1.50",
    "port": 8000,
    "framework": "langchain",
    "path": "/docs",
    "url": "http://192.168.1.50:8000/docs"
  },
  "timestamp": "ISO8601"
}
```
