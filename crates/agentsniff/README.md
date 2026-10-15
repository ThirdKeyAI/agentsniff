# AgentSniff (Rust v2)

**AI Agent Network Scanner** — Detect AI agents operating on your network through passive monitoring, active probing, protocol detection, and behavioral analysis.

[Documentation](https://docs.agentsniff.org/) · [Website](https://agentsniff.org) · [GitHub](https://github.com/ThirdKeyAI/agentsniff)

## Install

```bash
cargo install agentsniff
```

The binary statically embeds the dashboard HTML and the signed signature files, so the single `agentsniff` executable is fully self-contained.

If you'd rather skip the Rust toolchain, pre-built binaries for Linux (x86_64 / aarch64), macOS (Apple Silicon / Intel), and Windows (x86_64) are attached to every [GitHub release](https://github.com/ThirdKeyAI/agentsniff/releases/latest), each signed keyless with [Sigstore cosign](https://docs.sigstore.dev/). On Linux / macOS:

```bash
curl -fsSL https://agentsniff.org/install.sh | bash
```

The installer auto-detects your platform, verifies the SHA256 checksum, and drops the binary at `~/.agentsniff/bin/`.

## Quick Start

```bash
# Scan a subnet
agentsniff scan 192.168.1.0/24

# Continuous monitoring
agentsniff scan 192.168.1.0/24 --continuous 60

# Start the web dashboard
agentsniff serve --port 9090

# Verify a presented AgentPin credential from standard input
agentsniff verify-agentpin \
  --trust-bundle agentpin-trust-bundle.json \
  --audience verifier.example < credential.jwt
```

The dashboard server can also expose this verifier through
`POST /api/agentpin/verify` and the `verify_agentpin_credential` MCP tool at
`POST /mcp`. Configure `agentpin_trust_bundle_path`,
`agentpin_pin_store_path`, and `agentpin_expected_audience` in the server YAML;
callers cannot replace those trust inputs.

## Detection Modules

- **DNS Monitor** — Passive DNS for LLM API domain queries
- **Port Scanner** — Async TCP scan of agent-related ports
- **AgentPin Prober** — current-format `.well-known/agent-identity.json` discovery (unsigned, medium confidence); presented credentials can be verified separately against an out-of-band trust bundle
- **MCP Detector** — JSON-RPC 2.0 / SSE probing for MCP servers
- **Endpoint Prober** — HTTP framework fingerprinting (LangChain, CrewAI, Dify, …)
- **TLS Fingerprint** — JA3 fingerprinting of agent HTTP clients
- **Traffic Analyzer** — Behavioral pattern analysis
- **SSE Detector** — LLM streaming connection detection

Plus optional integrations: Zeek log ingestion (`--zeek-logs`) service enrichment with naabu, httpx and zgrab2 (`--enrich`), and import of your own Nmap XML results (`--nmap-xml`).

Signals are correlated into deterministic `(IP, port, transport)` service assets. Presence confidence, cryptographic identity assurance, and risk are reported separately. Completed scans are compared with the latest persisted scan of the same target/detector scope, and alerts default to new, changed, or removed assets only.

## Optional Features

```bash
# eBPF passive capture (requires a nightly Rust toolchain — the nested
# eBPF crate pins nightly via its own rust-toolchain.toml, so cargo
# picks it up automatically as long as nightly is installed via rustup).
cargo install agentsniff --features ebpf
```

## Requirements

- Rust 1.75+ (stable)
- Linux recommended (passive capture); `--features ebpf` needs a recent kernel + nightly toolchain
- Root / `CAP_NET_RAW` optional (enables passive DNS, TLS, and traffic monitoring; otherwise falls back to active probing)

## License

Apache-2.0 — Jascha Wanger / ThirdKey AI
