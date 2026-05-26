# CLI Reference

The CLI surface is identical between v1 (Python) and v2 (Rust). Every flag documented here is supported on both.

## Commands

```
agentsniff <command> [options]
```

| Command | Description |
|---------|-------------|
| `scan` | Run a network scan |
| `serve` | Start web dashboard API server |
| `init-config` | Generate default configuration file |
| `update-signatures` | Download and verify detection signatures from GitHub |

## scan

```bash
agentsniff scan [network] [options]
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `network` | Target network CIDR | `192.168.1.0/24` |

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--hosts HOST,HOST` | Specific hosts to scan | — |
| `--exclude HOST,HOST` | Hosts to exclude | — |
| `--config FILE` | YAML configuration file | — |
| `--format FORMAT` | Output format: `table`, `json`, `csv` | `table` |
| `--output FILE` | Save results to file | — |
| `--detectors D,D` | Enable specific detectors only | all |
| `--timeout SECS` | HTTP timeout | `5.0` |
| `--concurrency N` | Max concurrent connections | `100` |
| `--continuous SECS` | Repeat scan every N seconds | — |
| `--webhook-url URL` | Webhook URL for alerts (auto-enables alerting) | — |
| `--smtp-to ADDR,ADDR` | Email recipients for alerts (auto-enables alerting) | — |
| `--db PATH` | SQLite database path | `~/.agentsniff/agentsniff.db` |
| `--log-file PATH` | Log file path | — |
| `--zeek-logs PATH` | Zeek JSON log directory (enables Zeek integration) | — |
| `--nmap` | Enable nmap enrichment after detection | `false` |
| `--nmap-args ARGS` | nmap scan arguments | `-sV` |
| `-v, --verbose` | Debug logging | `false` |
| `-q, --quiet` | Minimal output | `false` |

### Examples

```bash
# Basic scan
agentsniff scan 192.168.1.0/24

# Scan specific hosts with JSON output
agentsniff scan --hosts 10.0.0.1,10.0.0.2 --format json

# Continuous monitoring with webhook
agentsniff scan 192.168.1.0/24 --continuous 300 \
  --webhook-url https://hooks.example.com/agentsniff

# Use only fast detectors
agentsniff scan 192.168.1.0/24 --detectors port_scanner,endpoint_prober

# With Zeek log ingestion
agentsniff scan 192.168.1.0/24 --zeek-logs /opt/zeek/logs/current/

# With nmap enrichment
agentsniff scan 192.168.1.0/24 --nmap --nmap-args "-sV -O"
```

## serve

```bash
agentsniff serve [options]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host ADDR` | Bind address | `0.0.0.0` |
| `--port PORT` | Bind port | `9090` |
| `--network CIDR` | Default scan target | `192.168.1.0/24` |
| `--db PATH` | SQLite database path | `~/.agentsniff/agentsniff.db` |
| `--log-file PATH` | Log file path | — |

### Examples

```bash
# Default
agentsniff serve

# Custom port and target
agentsniff serve --port 8080 --network 10.0.0.0/24

# With persistent storage
agentsniff serve --db /var/lib/agentsniff/scans.db \
  --log-file /var/log/agentsniff/server.log
```

## init-config

Generate a default configuration file.

```bash
agentsniff init-config                          # writes ./agentsniff.yaml
agentsniff init-config --output myconfig.yaml   # custom path (v2)
agentsniff init-config --force                  # overwrite existing file (v2)
```

| Option | Description | Default |
|--------|-------------|---------|
| `--output PATH` | Path for the generated YAML (v2 only) | `agentsniff.yaml` |
| `--force` | Overwrite an existing file (v2 only) | `false` |

## update-signatures

Download and (optionally) verify the detection signature files from the official source.

```bash
agentsniff update-signatures
agentsniff update-signatures --no-verify
agentsniff update-signatures --url https://signatures.example.com/  # v2 only
```

| Option | Description | Default |
|--------|-------------|---------|
| `--verify` | Verify SchemaPin signatures after download | `true` |
| `--no-verify` | Skip signature verification | `false` |
| `--url BASE` | Custom base URL for signature files (v2 only) | — |

The signatures are signed with ECDSA-P256 against an embedded public key; if `--verify` is on (default), any tampered file aborts the update.
