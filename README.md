# AgentSniff

AgentSniff is a Rust network scanner for discovering AI-agent infrastructure through active probing, passive monitoring, protocol detection, and behavioral analysis.

[Documentation](https://docs.agentsniff.org/) · [Website](https://agentsniff.org) · [GitHub](https://github.com/ThirdKeyAI/agentsniff)

## Detection model

| Detector | Method | Passive privileges | Typical confidence |
|---|---|---:|---:|
| DNS monitor | LLM and agent-infrastructure domains | Optional | High |
| Port scanner | Agent, MCP, inference, and vector-service ports | No | Low–Medium |
| AgentPin prober | `/.well-known/agent-identity.json` discovery | No | Medium |
| MCP detector | JSON-RPC initialization and capability enumeration | No | High–Confirmed |
| Endpoint prober | Framework endpoints, metadata, headers, and OpenAPI | No | Medium–High |
| TLS fingerprint | ClientHello fingerprints and active TLS probes | Optional | High |
| Traffic analyzer | LLM/API and burst behavior | Optional | Medium–High |
| SSE detector | Long-lived event-stream traffic | Optional | High |

AgentPin documents are currently treated as unsigned discovery evidence. AgentSniff validates their shape, but it does not yet implement the AgentPin signature, delegation, expiry, and revocation profile. Consequently, an AgentPin document alone is not labeled “identity verified” and cannot produce a `CONFIRMED` signal.

Signals from all enabled detectors are correlated by source host using noisy-OR scoring.

## Install

### Cargo

```bash
cargo install agentsniff --locked
agentsniff scan 192.168.1.0/24
```

For optional Linux eBPF capture:

```bash
cargo install agentsniff --locked --features ebpf
```

### Release archive

The installer requires [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and fails closed unless the archive was signed by this repository’s release workflow for the selected tag.

```bash
curl -fsSL https://agentsniff.org/install.sh | bash
```

Manual verification uses the exact workflow identity and release tag:

```bash
cosign verify-blob \
  --certificate agentsniff-<tag>-<target>.tar.gz.pem \
  --signature agentsniff-<tag>-<target>.tar.gz.sig \
  --certificate-identity="https://github.com/ThirdKeyAI/agentsniff/.github/workflows/release-binaries.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  agentsniff-<tag>-<target>.tar.gz
```

### From source

```bash
git clone https://github.com/ThirdKeyAI/agentsniff.git
cd agentsniff
cargo build --locked --release
./target/release/agentsniff --help
```

The workspace, lockfile, and Rust crates live at repository top level. The legacy Python implementation has been retired.

### Docker

The default Compose service is active-scanning only, publishes the dashboard to host loopback, and receives no raw-network capabilities.

```bash
export AGENTSNIFF_API_TOKEN="$(openssl rand -hex 32)"
docker compose up -d
# http://127.0.0.1:9090
```

Passive capture is an explicit privileged profile:

```bash
docker compose --profile passive up -d agentsniff-passive
```

The passive profile uses host networking plus `NET_RAW` and `NET_ADMIN`. Use it only on a trusted scanner host.

## CLI

```text
agentsniff <command> [options]

Commands:
  scan                 Run a network scan
  serve                Start the dashboard and API
  init-config          Generate a configuration file
  update-signatures    Download a complete verified signature set
```

Examples:

```bash
agentsniff scan 192.168.1.0/24
agentsniff scan --hosts server1,server2
agentsniff scan 10.0.0.0/24 --format json --output results.json
agentsniff scan 192.168.1.0/24 --continuous 300
agentsniff serve --port 9090
```

A scan is limited to 65,536 resolved targets. Larger ranges are rejected before address materialization.

## Dashboard security

`agentsniff serve` binds to `127.0.0.1` by default. Loopback use remains credential-free. Set `AGENTSNIFF_API_TOKEN` to enable Basic/Bearer authentication; a token of at least 32 bytes is mandatory before AgentSniff will bind to a non-loopback address.

- Keep the listener on loopback for local use.
- For remote access, use TLS and set a strong `AGENTSNIFF_API_TOKEN`; an authenticated reverse proxy can provide additional authorization and rate limiting.
- The browser dashboard uses HTTP Basic authentication with username `agentsniff` and the configured token as its password. API clients may send the token as a Bearer credential.
- `/api/health` remains public for health checks; every other dashboard and API route is authenticated when a token is configured.
- Cross-origin API access is disabled, scan creation requires a JSON `POST`, and SSE is read-only.

Start a scan through the API:

```bash
curl --fail --request POST http://127.0.0.1:9090/api/scan \
  --header "Authorization: Bearer ${AGENTSNIFF_API_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data '{"network":"192.168.1.0/24"}'
```

Core endpoints:

| Endpoint | Method | Purpose |
|---|---:|---|
| `/` | GET | Dashboard |
| `/api/health` | GET | Health check |
| `/api/scan` | POST JSON | Start a scan |
| `/api/scan/status` | GET | Current scan status |
| `/api/scan/results` | GET | Latest results |
| `/api/scan/stream` | GET/SSE | Read-only live events |
| `/api/scan/stop` | POST JSON | Stop the running scan |
| `/api/scan/history` | GET | Scan history |
| `/api/scan/sarif` | GET | SARIF export |
| `/api/settings` | GET/PUT | Alert settings |
| `/api/settings/test` | POST JSON | Send a test alert |
| `/api/db/backup` | GET | Download a SQLite snapshot |
| `/api/db/reset` | POST JSON | Delete scan history |

## Detection signatures

Detection data is embedded from `crates/agentsniff/assets/signatures/`. Every dataset is accepted only when its ECDSA P-256 signature verifies against the independently packaged `signing_key.pub`.

```bash
agentsniff update-signatures
```

Updates are downloaded as a complete set, verified against the pinned key, staged, re-verified, and atomically activated. Missing, partial, invalid, or differently signed data is rejected and the last known-good set remains active.

Maintainers can re-sign changed datasets with:

```bash
python3 scripts/resign_signatures.py --key ~/.agentsniff/keys/signing_key.pem frameworks.json
```

The helper refuses to sign when the private key does not correspond to the tracked trust anchor. The private key must never be committed.

## Configuration and storage

Generate a configuration:

```bash
agentsniff init-config
```

Important defaults:

```yaml
target_network: "192.168.1.0/24"
api_host: "127.0.0.1"
api_port: 9090
# Prefer the AGENTSNIFF_API_TOKEN environment variable for this secret.
api_token: ""
storage:
  backend: "sqlite"
  sqlite_path: "~/.agentsniff/agentsniff.db"
```

SQLite is the default persistent backend. PostgreSQL and Redis implementations are available in the Rust source, but verify deployment support for your selected command path before relying on them. Full scan results can contain sensitive network inventory; protect the database and backups accordingly.

## Optional integrations

- `--nmap` enriches detections with a locally installed `nmap` binary.
- `--zeek-logs PATH` consumes Zeek JSON logs.
- `--features ebpf` builds Linux eBPF passive-capture support.

Raw sockets, eBPF, host networking, and network-administration capabilities expand the scanner’s trust boundary. Enable only the minimum required for the chosen detectors.

## Development

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --lib --bins -- -D warnings
```

Useful paths:

```text
Cargo.toml
crates/agentsniff/                 Main library and binary
crates/agentsniff-common/          Shared eBPF/user-space types
crates/agentsniff/assets/          Dashboard and signed detection data
crates/agentsniff/tests/           Integration tests
scripts/                           Installer and maintainer signing tools
docs/                              Documentation site
```

## Responsible use

AgentSniff is intended for authorized network scanning and security assessment only. Scan only systems you own or have explicit permission to test.

## License

Apache License 2.0 — Copyright Jascha Wanger / ThirdKey AI
