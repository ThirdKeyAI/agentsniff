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

## probe

```bash
agentsniff probe IP:PORT --detectors D,D [--rate N] [--timeout SECS] [--max-time SECS] [--config FILE]
```

Checks one host and port with the named active detectors, for example to
retest a finding. Prints that endpoint's agent record as JSON on stdout. This
is the same shape as one entry of a scan's `agents[]`.

- Sends traffic only to `IP:PORT`: no discovery, no other ports or hosts, no DNS lookups, no update checks, no telemetry, and no HTTP redirects followed.
- `--detectors` is required. Accepted values: `port_scanner`, `endpoint_prober`, `mcp_detector`, `a2a_detector`, `agentpin_prober`, `tls_fingerprint`. Passive detectors are rejected.
- `--rate N` caps TCP connections and HTTP requests combined, at N per second. N can be fractional, for example `0.5`.
- `--timeout` (default 5s) bounds each connection and request. `--max-time` (default 600s) bounds the whole probe.
- Exit 0 with a record whose `signals` is empty means the target is not an agent. A non-zero exit means a tool failure: a bad argument, a rejected detector, or `--max-time` exceeded.

Approximate requests per detector, for sizing `--max-time` under `--rate`: `endpoint_prober` ~150, `mcp_detector` ~30, `port_scanner` 1, `a2a_detector` 1–3, `tls_fingerprint` 1–2, `agentpin_prober` 1–2.

### Stable identifiers

A finding is "still present" when the same `detector` reports the same `signal_type` on the same host and port. These identifiers are stable across versions:

| detector | signal_type |
|----------|-------------|
| `port_scanner` | `agent_service_identified`, `custom_agent_port_open`, `open_agent_port` |
| `endpoint_prober` | `framework_header_match`, `framework_endpoint_match`, `agent_metadata_found`, `agent_openapi_spec` |
| `mcp_detector` | `mcp_server_confirmed`, `mcp_agentpin_binding_advertised`, `mcp_tools_enumerated`, `mcp_resources_enumerated`, `mcp_prompts_enumerated` |
| `a2a_detector` | `a2a_agent_card_discovered`, `a2a_agent_card_signed_untrusted`, `a2a_agent_card_identity_verified`, `a2a_agent_card_signature_invalid` |
| `agentpin_prober` | `agentpin_unsigned_document` |
| `tls_fingerprint` | `tls_endpoint_detected` |

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
