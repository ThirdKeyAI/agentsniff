# CLI Reference

```text
agentsniff <command> [options]
```

| Command | Description |
|---|---|
| `scan` | Run a network scan |
| `serve` | Start the dashboard API |
| `verify-agentpin` | Verify a presented AgentPin credential |
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
| `--enrich` | Enrich detected agents with naabu, httpx and zgrab2 |
| `--nmap-xml FILE` | Import your own Nmap XML results (never runs Nmap) |

`--nmap` and `--nmap-args` were removed in 2.3.0 and now exit with an error.

Networks resolving above 65,536 targets are rejected before expansion.

## enrich

```bash
agentsniff enrich --input scan.json --nmap-xml scan.xml [-o enriched.json]
```

Applies your own Nmap XML results to a saved JSON scan (`scan -f json`). Makes no network connections and never runs Nmap.

## serve

```bash
agentsniff serve [--host 127.0.0.1] [--port 9090]
```

Loopback is the credential-free default. Non-loopback binding is refused unless `AGENTSNIFF_API_TOKEN` contains at least 32 bytes. The token protects all non-health routes through HTTP Basic authentication (username `agentsniff`) or an API Bearer token; remote deployments must use TLS.

## verify-agentpin

```bash
agentsniff verify-agentpin \
  --trust-bundle agentpin-trust-bundle.json \
  --audience verifier.example < credential.jwt
```

Use `--credential-file PATH` instead of standard input when needed. `--pin-store PATH` defaults to `~/.agentsniff/agentpin-pins.json`.

The trust bundle is an authenticated, out-of-band AgentPin bundle containing discovery and current revocation documents. AgentSniff requires exactly one of each for the credential issuer and every domain in its delegation chain. It deliberately performs no network fetches from untrusted JWT claims.

Successful and rejected verification results are emitted as JSON. A verified credential exits `0`, a cryptographic or policy rejection exits `2`, and invalid command input or unreadable files exit `1`. TOFU pin updates are persisted only after every check succeeds. See [AgentPin credential verification](agentpin-verification.md) for the complete trust and rotation model.

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
