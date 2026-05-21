# Configuration

AgentSniff can be configured via YAML file, environment variables, or CLI flags.

## YAML Configuration

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
api_enabled: false
api_host: "0.0.0.0"
api_port: 9090

# Storage (v1)
db_path: ""       # default: ~/.agentsniff/agentsniff.db
log_file: ""      # empty = console only

# Storage (v2) — multi-backend block; v1 ignores this
# storage:
#   backend: "sqlite"          # "sqlite" | "postgres" | "redis"
#   sqlite_path: "~/.agentsniff/agentsniff.db"
#   postgres_url: ""           # e.g. postgres://user:pass@host/db
#   redis_url: ""              # e.g. redis://host:6379/0

# Custom detection signatures
custom_llm_domains: []
custom_agent_ports: {}
custom_framework_signatures: {}

# Alerting
alert_enabled: false
alert_min_agents: 1
alert_min_confidence: low    # low, medium, high, confirmed
alert_cooldown: 0            # seconds between repeated alerts

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

nmap_enabled: false
nmap_scan_args: "-sV"
nmap_timeout: 120
```

## Environment Variables

All configuration options can be set via environment variables with the `AGENTSNIFF_` prefix:

```bash
export AGENTSNIFF_TARGET_NETWORK="10.0.0.0/16"
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
    endpoints:
      - "/api/agent/status"
      - "/api/agent/run"
    user_agents:
      - "my-agent-framework"
    headers:
      - "x-my-framework-version"
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

### Multi-backend storage (v2 only)

The Rust build adds PostgreSQL and Redis storage backends behind the same `StorageBackend` trait. Select via the `storage` block in YAML:

```yaml
storage:
  backend: "sqlite"           # "sqlite" | "postgres" | "redis"
  sqlite_path: "~/.agentsniff/agentsniff.db"
  postgres_url: ""            # e.g. postgres://user:pass@host/db
  redis_url: ""               # e.g. redis://host:6379/0
```

Or via env vars: `AGENTSNIFF_STORAGE_BACKEND`, `AGENTSNIFF_POSTGRES_URL`, `AGENTSNIFF_REDIS_URL`. The `--db` CLI flag still overrides `sqlite_path` and applies to all backends that need a local fallback path.
