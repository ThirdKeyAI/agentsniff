# AgentSniff Development Guide

AgentSniff is a Rust workspace for authorized AI-agent network discovery.

## Stack

- Rust 2021 workspace with Tokio
- Axum dashboard/API
- Reqwest active probes
- SQLite persistence through rusqlite
- Single-file embedded HTML/JS/CSS dashboard
- Optional eBPF, Zeek, and nmap integrations

## Layout

```text
Cargo.toml
crates/agentsniff/
  src/
    main.rs
    scanner.rs
    server.rs
    config.rs
    models.rs
    fusion.rs
    storage*.rs
    notifier.rs
    detectors/
    integrations/
    signatures/
  assets/
    index.html
    signatures/
  tests/
crates/agentsniff-common/
scripts/
docs/
```

## Invariants

- AgentPin shape validation is discovery only. Do not use “verified” or `CONFIRMED` without cryptographic identity validation.
- Detection datasets must verify against `assets/signatures/signing_key.pub`; never trust a key supplied by a sidecar.
- Signature updates are complete-set, fail-closed, and atomically activated.
- The dashboard binds to loopback by default. A non-loopback listener requires a 32-byte-or-longer API token, and every non-health route must remain authenticated when a token is configured.
- SSE is read-only; scan creation is a JSON POST.
- Network-derived strings must be inert in HTML and terminal output.
- Enforce target and response-size budgets before allocation.

## Commands

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --lib --bins -- -D warnings
cargo run -p agentsniff -- scan 192.168.1.0/24
cargo run -p agentsniff -- serve --port 9090
```

Raw capture requires appropriate Linux capabilities. Keep privileged Docker and host-network use opt-in.
