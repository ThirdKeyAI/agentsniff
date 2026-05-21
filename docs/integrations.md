# Integrations

AgentSniff supports optional integrations with external tools that enrich detection without adding required dependencies. v1 stays pure Python; v2 ships the same integrations behind config flags with no extra build step.

## Zeek (Data Source)

Zeek integration reads JSON log files (or TSV in v2) and feeds normalized records to the traffic analyzer and DNS monitor detectors. There is no runtime Zeek binary dependency on either version — AgentSniff just reads log files that Zeek has already written.

### Setup

Point AgentSniff at your Zeek JSON log directory:

```bash
agentsniff scan 192.168.1.0/24 --zeek-logs /opt/zeek/logs/current/
```

Or via configuration:

```yaml
zeek_enabled: true
zeek_log_path: "/opt/zeek/logs/current/"
zeek_time_window: 300  # seconds of logs to read
```

### Supported Log Files

| Log File | Used By | Data |
|----------|---------|------|
| `conn.log` | Traffic Analyzer | Connection records (src/dst IP, ports, duration, bytes) |
| `dns.log` | DNS Monitor | DNS queries and responses |
| `ssl.log` | TLS Fingerprint | TLS handshake data (server name, JA3 hash) |

### How It Works

When a Zeek data source is configured, detectors skip raw socket setup and use the provided records instead. Analysis logic (burst detection, ORA-loop, LLM API matching) stays identical — only the input source changes.

```
Zeek JSON logs → ZeekDataSource → Normalized records → Existing detectors
```

## nmap (Enricher)

nmap integration is a post-processing step that runs after detection and correlation. It scans only IPs where agents were already detected — not the full target range.

### Setup

Both versions just need the `nmap` binary on `$PATH`:

```bash
# Debian / Ubuntu
sudo apt install nmap

# v1: optional pip extra also installs the python-nmap wrapper
pip install agentsniff[nmap]

# v2: no extra build step, just have `nmap` available
```

```bash
# Same flags on both versions
agentsniff scan 192.168.1.0/24 --nmap
agentsniff scan 192.168.1.0/24 --nmap --nmap-args "-sV -O"
```

Or via configuration:

```yaml
nmap_enabled: true
nmap_scan_args: "-sV"
nmap_timeout: 120
```

### Enrichment Outcomes

For each detected agent, nmap produces one of three outcomes:

| Outcome | Condition | Action |
|---------|-----------|--------|
| **Boost** | nmap confirms agent-like service (Uvicorn, Node.js, Ollama) | Add corroborating signal |
| **Exclude** | nmap identifies non-agent service (CUPS, PostgreSQL, Apache) | Downgrade to INFO status |
| **Neutral** | Ambiguous or unknown service | Add service info to metadata |

### Exclusion Logic

Non-agent services (CUPS, PostgreSQL, MySQL, Redis, SSHD, etc.) are downgraded to INFO status only if the port scanner is the sole signal. If endpoint_prober or mcp_detector corroborates the detection, the agent stays — it's likely reverse-proxying an agent.

### Agent-Like Services

Services that corroborate agent detection: Uvicorn, Gunicorn, Node.js, Deno, Flask, FastAPI, Express, Starlette, Ollama, vLLM, TGI, Triton.
