# Architecture

AgentSniff is a Rust workspace built around asynchronous detector execution and per-host signal fusion.

```text
CLI / loopback dashboard
          |
       Axum API
          |
      scan manager
          |
  detector registry -------- optional Zeek/nmap/eBPF
          |
   signals by host
          |
 noisy-OR fusion
          |
 SQLite / alerts / SARIF / SSE
```

## Main components

| Path | Responsibility |
|---|---|
| `crates/agentsniff/src/main.rs` | CLI and output |
| `crates/agentsniff/src/scanner.rs` | Target resolution and orchestration |
| `crates/agentsniff/src/server.rs` | Axum dashboard API and read-only SSE |
| `crates/agentsniff/src/models.rs` | Signals, agents, results, confidence |
| `crates/agentsniff/src/fusion.rs` | Cross-detector fusion |
| `crates/agentsniff/src/detectors/` | Eight detector modules |
| `crates/agentsniff/src/integrations/` | Zeek and nmap |
| `crates/agentsniff/src/signatures/` | Pinned-key dataset verification and updates |
| `crates/agentsniff/assets/` | Embedded dashboard and signed data |
| `crates/agentsniff-common/` | Shared eBPF/user-space types |

## Trust boundaries

Scanned hosts and all response content are untrusted. Detection datasets cross a distribution boundary and are accepted only under the packaged public key. The management API binds loopback by default, disables cross-origin access, and requires JSON POST for scan creation. Non-loopback binding requires a strong API token that authenticates every non-health route; remote deployments must add TLS and may use a reverse proxy for additional authorization and rate limiting.

Passive capture, host networking, eBPF, and nmap expand local privilege and resource boundaries. The default Compose service omits those privileges, while the passive profile opts in explicitly.

## Identity semantics

AgentPin structure validation establishes only that a target serves a plausible discovery document. It does not establish issuer ownership. AgentSniff therefore emits an unsigned medium-confidence discovery signal until cryptographic AgentPin validation is implemented.

Detection-data signatures are a separate control: ECDSA P-256 sidecars verify against the independently packaged `signing_key.pub`. A key inside a sidecar cannot replace that trust anchor.
