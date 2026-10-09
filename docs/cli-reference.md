# CLI Reference

```text
agentsniff <command> [options]
```

| Command | Description |
|---|---|
| `scan` | Run a network scan |
| `serve` | Start the dashboard API |
| `init-config` | Generate configuration |
| `update-signatures` | Download and atomically activate a verified signature set |

## scan

```bash
agentsniff scan [network] [options]
```

Common options:

| Option | Description |
|---|---|
| `--hosts HOST,HOST` | Additional targets |
| `--exclude HOST,HOST` | Excluded hosts |
| `--config FILE` | YAML configuration |
| `--format table|json|csv` | Output format |
| `--output FILE` | Save output |
| `--detectors D,D` | Select detectors |
| `--timeout SECS` | HTTP timeout |
| `--concurrency N` | Concurrent connections |
| `--continuous SECS` | Repeat interval |
| `--db PATH` | SQLite path |
| `--zeek-logs PATH` | Zeek JSON log directory |
| `--nmap` | Enable nmap enrichment |
| `--nmap-args ARGS` | nmap arguments |

Networks resolving above 65,536 targets are rejected before expansion.

## serve

```bash
agentsniff serve [--host 127.0.0.1] [--port 9090]
```

Loopback is the credential-free default. Non-loopback binding is refused unless `AGENTSNIFF_API_TOKEN` contains at least 32 bytes. The token protects all non-health routes through HTTP Basic authentication (username `agentsniff`) or an API Bearer token; remote deployments must use TLS.

## init-config

```bash
agentsniff init-config
agentsniff init-config --output agentsniff.yaml
agentsniff init-config --force
```

## update-signatures

```bash
agentsniff update-signatures
agentsniff update-signatures --url https://signatures.example.com/
```

Verification cannot be disabled. Every file must verify against the packaged `signing_key.pub`; the complete staged set is re-verified before atomic activation.
