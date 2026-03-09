# API Reference

When running `agentsniff serve`, a REST API is available with the following endpoints.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `GET /` | — | Web dashboard |
| `GET /docs` | — | Swagger / OpenAPI docs |
| `GET /api/health` | — | Health check |
| `POST /api/scan` | `?network=CIDR` | Start a scan |
| `POST /api/scan/stop` | — | Stop running scan |
| `GET /api/scan/status` | — | Current scan status |
| `GET /api/scan/results` | — | Latest scan results |
| `GET /api/scan/history` | `?limit=&offset=` | Previous scan results |
| `GET /api/scan/{scan_id}` | — | Specific historical scan |
| `GET /api/agents` | — | All detected agents |
| `GET /api/scan/stream` | SSE | Real-time scan streaming |
| `GET /api/settings` | — | Get alert settings |
| `PUT /api/settings` | JSON body | Update alert settings |
| `POST /api/settings/test` | — | Send test alert |

## SSE Streaming

The `/api/scan/stream` endpoint provides real-time scan updates via Server-Sent Events:

```
GET /api/scan/stream?network=192.168.1.0/24&detectors=port_scanner,endpoint_prober
```

### Event Types

| Event | Data | Description |
|-------|------|-------------|
| `scan_started` | `{"scan_id", "detectors", "target"}` | Scan has begun |
| `agent_detected` | Agent JSON object | New agent found or updated |
| `scan_complete` | Full scan result JSON | Scan finished |
| `scan_error` | `{"error"}` | Scan failed |

### Example

```javascript
const source = new EventSource('/api/scan/stream?network=192.168.1.0/24');

source.addEventListener('agent_detected', (e) => {
  const agent = JSON.parse(e.data);
  console.log(`Found: ${agent.framework} at ${agent.ip_address}:${agent.port}`);
});

source.addEventListener('scan_complete', (e) => {
  const result = JSON.parse(e.data);
  console.log(`Done: ${result.agents.length} agents in ${result.duration_seconds}s`);
  source.close();
});
```

## Scan Result Schema

```json
{
  "scan_id": "uuid",
  "started_at": "ISO8601",
  "completed_at": "ISO8601",
  "target_network": "CIDR",
  "summary": {
    "total_agents": 3,
    "by_confidence": {"low": 0, "medium": 1, "high": 1, "confirmed": 1},
    "by_status": {"detected": 1, "suspected": 0, "verified": 2},
    "detectors_run": ["port_scanner", "endpoint_prober", "mcp_detector"],
    "duration_seconds": 4.2
  },
  "agents": [...]
}
```

## Agent Schema

```json
{
  "id": "uuid",
  "host": "hostname",
  "ip_address": "192.168.1.50",
  "port": 8000,
  "agent_type": "framework",
  "framework": "langchain",
  "status": "verified",
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
