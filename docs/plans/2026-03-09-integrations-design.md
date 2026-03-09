# Integrations Layer Design

## Goal

Add optional integrations with external tools (Zeek, nmap) that enrich AgentSniff's detection without adding required dependencies. The core scanner stays pure Python and zero-dependency. Power users opt in via config.

## Architecture

Two integration patterns under `agentsniff/integrations/`:

### DataSource (Zeek)

Provides normalized traffic/DNS/TLS records that existing detectors consume instead of raw sockets. Replaces "how we observe," not "what we look for."

- Reads Zeek JSON log files (`conn.log`, `dns.log`, `ssl.log`)
- No Zeek binary dependency — just reads log files from a configured path
- Time-windowed: only reads records from last N seconds (default 300s)
- For continuous mode, tracks file position to avoid re-reading

Detectors that support data sources (traffic_analyzer, dns_monitor) get an optional `data_source` parameter. When present, they skip raw socket setup and use the provided records. Analysis logic (burst detection, ORA-loop, LLM API matching) stays identical.

### Enricher (nmap)

Post-processing step that runs after detection and correlation. Takes detected agents, adds OS/service info, returns enriched list.

- Only scans IPs where agents were already detected (not the full target range)
- Uses `python-nmap` library (optional dependency: `pip install agentsniff[nmap]`)
- Three outcomes per agent:
  - **Boost**: nmap confirms agent-like service (Uvicorn, Node.js, Ollama) → add corroborating signal
  - **Exclude**: nmap identifies non-agent service (CUPS, PostgreSQL, plain Apache) → downgrade to INFO status
  - **Neutral**: ambiguous or unknown → add service info to metadata, leave confidence unchanged
- Exclusion respects existing corroboration: nginx/Apache only excluded if port_scanner is the sole signal

## File Structure

```
agentsniff/integrations/
├── __init__.py          # DataSource / Enricher base classes + registry
├── zeek.py              # ZeekDataSource
└── nmap.py              # NmapEnricher
```

## Data Types

Normalized records shared between data sources:

```python
@dataclass
class TrafficRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    bytes_sent: int
    bytes_recv: int

@dataclass
class DnsRecord:
    timestamp: float
    query: str
    qtype: str
    response_ips: list[str]
    src_ip: str

@dataclass
class TlsRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    server_name: str
    ja3_hash: str
    subject: str
    issuer: str
```

## Data Flow

### Zeek (DataSource)

```
run_scan()
  → detector.setup()
    → traffic_analyzer: ZeekDataSource configured?
      YES → zeek.load_records(targets, time_window) → TrafficRecord list
      NO  → raw socket capture (current behavior)
    → dns_monitor: ZeekDataSource configured?
      YES → zeek.load_dns_queries(targets) → DnsRecord list
      NO  → passive DNS capture (current behavior)
  → detector.scan() uses whichever data source provided records
```

### nmap (Enricher)

```
run_scan()
  → detectors produce signals
  → correlate_signals() → DetectedAgent list
  → apply_fusion_rules()
  → nmap_enricher.enrich(agents)
    → nmap -sV -O against agent IPs only
    → per agent:
      service matches agent framework → add NMAP_ENRICHER signal (boost)
      service is definitively non-agent → set status=INFO, add explanation
      ambiguous → add service info to metadata
  → return ScanResult
```

## Configuration

```yaml
integrations:
  zeek:
    enabled: false
    log_path: "/opt/zeek/logs/current/"
    log_formats: ["json"]
    time_window: 300
  nmap:
    enabled: false
    scan_args: "-sV -O --top-ports 100"
    timeout: 120
```

Off by default. Lazy imports — missing dependency raises a clear error, not an import crash.

## Model Changes

- Add `INFO` to agent status enum (below SUSPECTED, means "noted but not actionable")
- Add `NMAP_ENRICHER` to `DetectorType` enum
- Add `ZEEK` to `DetectorType` enum (for signals generated from Zeek data)

## Dependency Changes

```toml
[project.optional-dependencies]
nmap = ["python-nmap>=0.7"]
dev = [...]
```

Zeek has no Python dependency — it reads JSON log files using stdlib `json`.

## Detector Refactoring

Minimal changes to existing detectors. Add optional `data_source` parameter to constructor:

```python
class TrafficAnalyzerDetector(BaseDetector):
    def __init__(self, config, data_source: DataSource | None = None):
        self.data_source = data_source

    async def setup(self):
        if self.data_source:
            return  # skip raw socket setup
        # existing setup...
```

Same pattern for dns_monitor. No changes to scan() logic — just different input source.

## Non-Agent Service Exclusion

```python
NON_AGENT_SERVICES = {
    "cups", "postgresql", "mysql", "mariadb", "redis",
    "sshd", "postfix", "dovecot", "squid", "haproxy",
    "apache httpd", "nginx", "printer", "ipp",
}
```

Nginx/Apache get special handling: only excluded if port_scanner is the sole signal. If endpoint_prober or mcp_detector corroborates, the agent stays (likely reverse-proxying an agent).

## Testing

- Unit tests with fixture Zeek log files (JSON format)
- Unit tests for nmap enricher with mocked nmap output
- Integration test: Zeek logs → traffic_analyzer → signals match expected patterns
- Exclusion tests: verify non-agent services get INFO status, corroborated agents survive
