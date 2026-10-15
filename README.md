# AgentSniff

AgentSniff is a Rust network scanner for discovering AI-agent infrastructure through active probing, passive monitoring, protocol detection, and behavioral analysis.

[Documentation](https://docs.agentsniff.org/) · [Website](https://agentsniff.org) · [GitHub](https://github.com/ThirdKeyAI/agentsniff)

## Detection model

| Detector | Method | Passive privileges | Typical confidence |
|---|---|---:|---:|
| DNS monitor | LLM and agent-infrastructure domains | Optional | High |
| Port scanner | Agent, MCP, inference, and vector-service ports | No | Low–Medium |
| AgentPin prober | `/.well-known/agent-identity.json` discovery | No | Medium |
| A2A detector | Agent Card discovery and trusted JWS verification | No | High–Confirmed |
| MCP detector | Version-negotiated JSON-RPC discovery and capability enumeration | No | High–Confirmed |
| Endpoint prober | Framework endpoints, metadata, headers, and OpenAPI | No | Medium–High |
| TLS fingerprint | ClientHello fingerprints and active TLS probes | Optional | Low |
| Traffic analyzer | LLM/API and burst behavior | Optional | Medium–High |
| SSE detector | Long-lived event-stream traffic | Optional | High |

AgentPin discovery documents remain unsigned discovery evidence: a document alone is not labeled “identity verified” and cannot produce a `CONFIRMED` signal. Presented AgentPin credentials can be verified separately with `agentsniff verify-agentpin`. That fail-closed path checks the ES256 signature, time and key validity, agent status, capability and constraint narrowing, revocation, delegation signatures and depth, audience (when supplied), and persistent TOFU pins against an authenticated out-of-band trust bundle. AgentSniff also recognizes the AgentPin credential-binding capability advertised by MCP servers; that signal confirms only the advertised integration, not an agent identity or presented credential.

A2A Agent Cards are likewise self-asserted at `HIGH` confidence unless an ES256 JWS verifies against an out-of-band `a2a_trusted_keys` entry. Self-advertised keys never establish identity.

Signals from all enabled detectors are correlated into deterministic service assets keyed by IP, port, and transport (with a separate host-level asset for passive observations). Multiple services on one host remain distinct. Presence confidence, identity assurance, and security risk are reported independently: only a signature verified against an out-of-band trust anchor can produce `trusted_verified` identity assurance or the legacy `verified` status.

Completed scans are compared with the latest persisted scan of the same target scope. Assets are marked `new`, `changed`, or `unchanged`, removals are recorded in the scan diff, and `first_seen` survives across scans. Alerts default to new, changed, and removed assets only.

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
  verify-agentpin      Verify a presented AgentPin credential
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
agentsniff verify-agentpin \
  --trust-bundle agentpin-trust-bundle.json \
  --audience verifier.example < credential.jwt
```

A scan is limited to 65,536 resolved targets. Larger ranges are rejected before address materialization.

`verify-agentpin` never fetches a URL derived from an untrusted JWT. The supplied bundle must come from an authenticated out-of-band channel and contain exactly one discovery document and one revocation document for the issuer and every delegation domain. Credentials default to standard input so they do not need to appear in shell history or process arguments. See [AgentPin credential verification](docs/agentpin-verification.md).

`agentsniff serve` can expose the same verifier as
`POST /api/agentpin/verify` and as the `verify_agentpin_credential` tool on the
`POST /mcp` endpoint. The operator configures the trust bundle, expected
audience, and durable pin store; callers submit only the credential.

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
| `/api/agentpin/verify` | POST JSON | Verify a presented AgentPin credential |
| `/mcp` | POST JSON-RPC | AgentPin verification MCP tool |
| `/api/settings` | GET/PUT | Alert settings |
| `/api/settings/test` | POST JSON | Send a test alert |
| `/api/db/backup` | GET | Download a SQLite snapshot or PostgreSQL JSON export |
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

MCP Registry domains are maintained in a separate signed overlay. Its generator requires an explicit publisher allowlist, so community publication alone never promotes a hostname into a DNS indicator. TLS captures must be added with `scripts/add_tls_fingerprint.py`, which requires version, backend, timestamp, and local capture provenance.

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
  postgres_url: "" # prefer AGENTSNIFF_POSTGRES_URL
  redis_url: ""    # optional event fan-out; prefer AGENTSNIFF_REDIS_URL
```

SQLite is the default persistent backend. Set `backend: "postgres"` for shared PostgreSQL persistence; startup verifies the connection and applies embedded migrations before scanning or serving. Redis is an optional pub/sub event bus layered over either backend so multiple dashboard instances receive the same live scan events. It is not accepted as a persistence backend. Unsupported or incomplete storage selections fail at startup instead of silently falling back to SQLite. Full scan results can contain sensitive network inventory; protect databases, connection URLs, Redis, and backups accordingly.

## Optional integrations

- `--enrich` enriches detections with naabu, httpx and zgrab2 (included in the container image).
- `--nmap-xml FILE` imports your own Nmap XML results. AgentSniff never runs Nmap, and the image does not include it.
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
