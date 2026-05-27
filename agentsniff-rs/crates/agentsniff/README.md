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
curl -fsSL https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/scripts/install.sh | bash
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
```

## Detection Modules

- **DNS Monitor** — Passive DNS for LLM API domain queries
- **Port Scanner** — Async TCP scan of agent-related ports
- **AgentPin Prober** — `.well-known/agent-identity.json` discovery (confirmed identity)
- **MCP Detector** — JSON-RPC 2.0 / SSE probing for MCP servers
- **Endpoint Prober** — HTTP framework fingerprinting (LangChain, CrewAI, Dify, …)
- **TLS Fingerprint** — JA3 fingerprinting of agent HTTP clients
- **Traffic Analyzer** — Behavioral pattern analysis
- **SSE Detector** — LLM streaming connection detection

Plus optional integrations: Zeek log ingestion (`--zeek-logs`) and Nmap enrichment (`--nmap`).

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
