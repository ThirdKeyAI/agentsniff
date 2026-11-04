# Configuration

AgentSniff can be configured via YAML file, environment variables, or CLI flags.

For `scan` and `serve`, precedence is defaults → YAML → environment → explicitly
supplied CLI flags. Omitting a flag preserves the YAML/environment value.
Environment names are `AGENTSNIFF_` plus the upper-case field name; booleans accept
`true/false`, `yes/no`, `on/off`, or `1/0`; lists are comma-separated and maps
are JSON. Invalid environment values refuse startup without printing their contents.
Storage aliases are `AGENTSNIFF_STORAGE_BACKEND`, `AGENTSNIFF_DB_PATH`,
`AGENTSNIFF_POSTGRES_URL`, `AGENTSNIFF_REDIS_URL`, and `AGENTSNIFF_REDIS_CHANNEL`.
The AgentPin path/audience aliases remain `AGENTSNIFF_AGENTPIN_TRUST_BUNDLE`,
`AGENTSNIFF_AGENTPIN_PIN_STORE`, and `AGENTSNIFF_AGENTPIN_AUDIENCE`.

Changing a webhook/SMTP destination via environment overrides clears inherited
credentials unless replacement credentials are explicitly provided.
`dns_monitor_duration` controls the passive DNS observation window (maximum
3600 seconds). HTTP/port timeouts must be positive and no greater than 300 seconds;
concurrency must be between 1 and 1024.

### Resource and history limits

Scans retain at most 16 MiB of serialized result evidence, 16,384 signals total,
and 256 signals per asset. Large MCP catalogs and discovery metadata retain a
bounded sample with explicit truncation metadata. Passive timing capture is
limited to 1,024 flows, 2,048 samples per flow, and 32,768 samples overall.
Exceeding a capture/evidence budget marks results incomplete; incomplete results
cannot produce removal alerts.

History accepts at most 1,000 scans and a 512 MiB storage budget (SQLite database
pages; PostgreSQL serialized result payloads, excluding indexes and server WAL).
Oversized writes fail transactionally; existing history is not automatically
deleted. Export and reset history explicitly when the quota is reached. SQLite
files and sidecars use owner-only permissions on Unix. Backups use a consistent
SQLite snapshot or a streamed PostgreSQL JSON export, not an in-memory database copy.

## YAML Configuration

YAML uses a bounded, safe-Rust parser. Duplicate keys are rejected, merge keys
(`<<`) are not expanded, and booleans use `true`/`false` (not `yes`/`on`).
Quote numeric-looking strings such as tokens. Parser diagnostics do not include
surrounding source lines, which may contain credentials.

Generate a default config:

```bash
agentsniff init-config
# Creates agentsniff.yaml
```

Use it:

```bash
agentsniff scan --config agentsniff.yaml
```

### Full Configuration Reference

```yaml
# Network targets
target_network: "192.168.1.0/24"
target_hosts: []
exclude_hosts: []

# Detector modules (enable/disable)
enable_dns_monitor: true
enable_port_scanner: true
enable_agentpin_prober: true
enable_a2a_detector: true
enable_mcp_detector: true
enable_endpoint_prober: true
enable_tls_fingerprint: true
enable_traffic_analyzer: true
enable_sse_detector: true

# Scan parameters
port_scan_timeout: 2.0
port_scan_concurrency: 100
http_timeout: 5.0
http_concurrency: 100
dns_monitor_duration: 60
scan_interval: 0  # 0 = one-shot, >0 = continuous (seconds)

# Output
output_format: table  # table, json, csv
output_file: ""
verbose: false

# Web dashboard API
api_enabled: true
api_host: "127.0.0.1"
api_port: 9090
api_token: ""           # required for non-loopback; prefer AGENTSNIFF_API_TOKEN

# AgentPin REST/MCP verifier (disabled while trust bundle path is empty)
agentpin_trust_bundle_path: "/etc/agentsniff/agentpin-trust-bundle.json"
agentpin_pin_store_path: "~/.agentsniff/agentpin-pins.json"
agentpin_expected_audience: "verifier.example"

# Storage
db_path: ""       # default: ~/.agentsniff/agentsniff.db
log_file: ""      # empty = console only
storage:
  backend: "sqlite"
  sqlite_path: "~/.agentsniff/agentsniff.db"
  postgres_url: ""            # prefer AGENTSNIFF_POSTGRES_URL
  redis_url: ""               # optional live event bus
  redis_channel: "agentsniff:events:v1"

# Custom detection signatures
custom_llm_domains: []
custom_agent_ports: {}
custom_framework_signatures: {}
a2a_trusted_keys: {}

# Alerting
alert_enabled: false
alert_changes_only: true     # only new, changed, and removed assets
alert_min_agents: 1
alert_min_confidence: 0.5    # fused presence score from 0.0 to 1.0
alert_cooldown: 300          # seconds between repeated alerts

# Webhook
webhook_url: ""
webhook_headers: {}

# Email (SMTP)
smtp_host: ""
smtp_port: 587
smtp_user: ""
smtp_password: ""
smtp_use_tls: true
smtp_from: ""
smtp_to: []

# Integrations
zeek_enabled: false
zeek_log_path: ""
zeek_time_window: 300

enrich_enabled: false   # naabu + httpx + zgrab2
enrich_timeout: 300
nmap_xml_import: ""     # your own `nmap -oX` results
```

## Environment Variables

All configuration options can be set via environment variables with the `AGENTSNIFF_` prefix:

```bash
export AGENTSNIFF_TARGET_NETWORK="10.0.0.0/16"
export AGENTSNIFF_API_TOKEN="$(openssl rand -hex 32)"
export AGENTSNIFF_AGENTPIN_TRUST_BUNDLE="/etc/agentsniff/agentpin-trust-bundle.json"
export AGENTSNIFF_AGENTPIN_PIN_STORE="/var/lib/agentsniff/agentpin-pins.json"
export AGENTSNIFF_AGENTPIN_AUDIENCE="verifier.example"
export AGENTSNIFF_ENABLE_DNS_MONITOR=true
export AGENTSNIFF_HTTP_TIMEOUT=10.0
export AGENTSNIFF_DB_PATH="/var/lib/agentsniff/scans.db"
export AGENTSNIFF_LOG_FILE="/var/log/agentsniff/scan.log"
```

Lists use comma-separated values:

```bash
export AGENTSNIFF_TARGET_HOSTS="server1,server2,server3"
export AGENTSNIFF_SMTP_TO="admin@example.com,security@example.com"
```

The AgentPin verifier is exposed only when both the trust-bundle path and
expected audience are configured. AgentSniff validates the files before the
server starts. MCP and REST callers submit only a credential; they cannot
replace the operator's trust bundle, audience, or TOFU pin store.

## Custom Signatures

### Custom LLM Domains

Add internal or private LLM API domains:

```yaml
custom_llm_domains:
  - "llm.internal.company.com"
  - "ai-gateway.corp.net"
```

### Custom Agent Ports

Add ports specific to your environment:

```yaml
custom_agent_ports:
  9000: "internal_agent"
  4567: "custom_mcp"
```

### Custom Framework Signatures

Define custom agent framework detection rules:

```yaml
custom_framework_signatures:
  my_framework:
    probe_paths:
      - "/api/agent/status"
      - "/api/agent/run"
    well_known_paths:
      - "/.well-known/my-agent.json"
    request_user_agents:
      - "my-agent-framework"
    response_header_names:
      - "x-my-framework-version"
    response_headers:
      server:
        - "my-agent/*"
    response_body_markers:
      - "my-agent-framework"
    json_predicates:
      - path: "capabilities.tools"
        exists: true
```

`request_user_agents` and `mcp_client_names` are passive indicators. Active HTTP probing only evaluates response headers, body markers, and JSON predicates.

### Trusted A2A signing keys

Map JWS `kid` values to out-of-band ES256 public keys. Do not copy a key from the Agent Card itself; that proves only self-consistency, not identity.

```yaml
a2a_trusted_keys:
  "production-agent-2026": |-
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
```

## Storage

AgentSniff persists scan history to a local SQLite database at `~/.agentsniff/agentsniff.db` by default. Created automatically on first use.

```bash
# Custom database path
agentsniff scan 192.168.1.0/24 --db /var/lib/agentsniff/scans.db

# Enable file logging
agentsniff scan 192.168.1.0/24 --log-file /var/log/agentsniff/scan.log
```

The database stores full scan results including detected agents and signals. The web dashboard's Scan History panel loads from the database, so history persists across server restarts.

### PostgreSQL and multi-instance events

Select SQLite for local operation or PostgreSQL for shared persistence. Redis is an optional pub/sub event bus for forwarding live SSE events between server instances; it does not store scan history.

```yaml
storage:
  backend: "postgres"         # "sqlite" | "postgres"
  sqlite_path: "~/.agentsniff/agentsniff.db"
  postgres_url: ""            # set AGENTSNIFF_POSTGRES_URL instead
  redis_url: ""               # set AGENTSNIFF_REDIS_URL to enable event fan-out
  redis_channel: "agentsniff:events:v1"
```

The corresponding environment variables are `AGENTSNIFF_STORAGE_BACKEND`, `AGENTSNIFF_POSTGRES_URL`, `AGENTSNIFF_REDIS_URL`, and `AGENTSNIFF_REDIS_CHANNEL`. Prefer environment or secret-manager injection for URLs containing credentials. The `--db` CLI flag overrides only `sqlite_path`.

AgentSniff verifies the selected backend and applies embedded PostgreSQL migrations before accepting work. Unknown backends, missing URLs, unreachable services, and the legacy `backend: "redis"` selection fail startup instead of falling back to SQLite. PostgreSQL stores the canonical scan result as JSONB with indexed history and baseline columns. Redis supports `redis://` and TLS `rediss://` URLs, uses a bounded event queue and payload limit, ignores its own echoed events, and reconnects subscribers after interruption.

`GET /api/db/backup` returns a SQLite snapshot for SQLite or a portable JSON scan export for PostgreSQL. `POST /api/db/reset` clears the selected backend.
