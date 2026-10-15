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

## Service enrichment (`--enrich`)

Service enrichment runs after detection and correlation. It checks only IPs where agents were already detected, not the full target range. It uses three permissively licensed tools, each run as a separate process with JSON output:

| Tool | License | Role |
|------|---------|------|
| [naabu](https://github.com/projectdiscovery/naabu) | MIT | Open TCP ports (connect scan, `-s c`, top 1000 ports) |
| [httpx](https://github.com/projectdiscovery/httpx) | MIT | Web server and technology detection on every open port |
| [zgrab2](https://github.com/zmap/zgrab2) | Apache-2.0 | Banners on the remaining non-HTTP ports (ssh, smtp, imap, pop3, ftp, redis, mysql, postgres, mongodb, memcached) |

The port each agent was detected on is always checked, even if it is outside naabu's top ports. ProjectDiscovery update checks are disabled (`-duc`), and results are never uploaded to ProjectDiscovery's cloud.

### Setup

The container image includes all three tools at pinned versions (see `third-party/README.md`). It does **not** include Nmap. Outside the container, put `naabu`, `httpx` and `zgrab2` on `$PATH`. A missing tool is skipped with a warning.

```bash
agentsniff scan 192.168.1.0/24 --enrich
```

Or via configuration:

```yaml
enrich_enabled: true
enrich_timeout: 300   # seconds per tool
```

### Classification

Server headers, technology names and successful zgrab2 modules are matched against two lists:

- **Agent-like** (Uvicorn, Gunicorn, Hypercorn, Node.js, Express, Ollama, LM Studio, vLLM, Streamlit, Gradio, FastAPI) adds a `service_match` signal from `service_enricher`.
- **Non-agent** (CUPS, PostgreSQL, MySQL, Redis, MongoDB, SSH, SMTP, IMAP, FTP, nginx, and similar) adds no detection signal. If every service on the host is non-agent and no other detector (endpoint, MCP, A2A, AgentPin, DNS, traffic, TLS or SSE) corroborates the agent, a `non_agent_services` signal is added and the confidence score is halved.
- Anything else counts as unknown.

Discovered services are stored in the agent's `enrich_services` metadata.

## Importing your own Nmap results (`--nmap-xml`)

AgentSniff does not run Nmap. If you run Nmap yourself, you can import its XML output (`nmap -oX`), and it is classified the same way:

```bash
nmap -sV -oX scan.xml 192.168.1.10
agentsniff scan 192.168.1.0/24 --nmap-xml scan.xml

# Or apply it to a saved JSON scan, with no network activity:
agentsniff scan 192.168.1.0/24 -f json -o scan.json
agentsniff enrich --input scan.json --nmap-xml scan.xml
```

Only hosts that are already detected agents are enriched. Imported services are stored in `nmap_services` metadata, with `nmap_service_match` signals.

### Removed in 2.3.0

`--nmap`, `--nmap-args` and the `nmap_enabled`, `nmap_scan_args` and `nmap_timeout` config keys were removed. Passing `--nmap` or setting `nmap_enabled: true` now fails with a pointer to `--enrich` and `--nmap-xml`. Other leftover `nmap_*` keys are ignored with a warning.
