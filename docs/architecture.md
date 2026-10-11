# Architecture

AgentSniff is a Rust workspace built around asynchronous detector execution and service-level signal fusion.

```text
CLI / loopback dashboard
          |
       Axum API
          |
      scan manager
          |
  detector registry -------- optional Zeek/nmap/eBPF
          |
 signals by service asset
          |
 noisy-OR fusion
          |
 identity + risk semantics
          |
 persisted scan diff
          |
 SQLite / delta alerts / SARIF / SSE
```

## Main components

| Path | Responsibility |
|---|---|
| `crates/agentsniff/src/main.rs` | CLI and output |
| `crates/agentsniff/src/scanner.rs` | Target resolution and orchestration |
| `crates/agentsniff/src/server.rs` | Axum dashboard API and read-only SSE |
| `crates/agentsniff/src/models.rs` | Signals, agents, results, confidence |
| `crates/agentsniff/src/baseline.rs` | Persisted scan-to-scan asset classification |
| `crates/agentsniff/src/fusion.rs` | Cross-detector fusion |
| `crates/agentsniff/src/detectors/` | Nine detector modules |
| `crates/agentsniff/src/integrations/` | Zeek and nmap |
| `crates/agentsniff/src/signatures/` | Pinned-key dataset verification and updates |
| `crates/agentsniff/assets/` | Embedded dashboard and signed data |
| `crates/agentsniff-common/` | Shared eBPF/user-space types |

## Trust boundaries

Scanned hosts and all response content are untrusted. Detection datasets cross a distribution boundary and are accepted only under the packaged public key. The management API binds loopback by default, disables cross-origin access, and requires JSON POST for scan creation. Non-loopback binding requires a strong API token that authenticates every non-health route; remote deployments must add TLS and may use a reverse proxy for additional authorization and rate limiting.

Passive capture, host networking, eBPF, and nmap expand local privilege and resource boundaries. The default Compose service omits those privileges, while the passive profile opts in explicitly.

## Identity semantics

AgentPin structure validation establishes only that a target serves a plausible current-format discovery document. It does not establish entity-domain ownership. AgentSniff therefore emits an unsigned medium-confidence discovery signal until cryptographic AgentPin validation is implemented.

A2A Agent Cards follow the same separation between discovery and identity. Structural validation produces discovery evidence; `trusted_verified` identity assurance requires an ES256 JWS that verifies against an administrator-configured, out-of-band `kid` trust anchor.

Detection-data signatures are a separate control: ECDSA P-256 sidecars verify against the independently packaged `signing_key.pub`. A key inside a sidecar cannot replace that trust anchor.

`presence_status` answers whether a service was detected; `identity_assurance` answers whether an identity claim was authenticated; `risk_level` records adverse evidence. These fields are intentionally independent. The legacy `status` field remains for compatibility, but `verified` is now reserved for `trusted_verified` identity assurance.

## Asset and baseline semantics

Active detector signals are correlated by `(IP, port, transport)`. Passive signals without a local service port use a host-level asset. Asset IDs are deterministic hashes of that key, so two services on one host do not overwrite one another and the same endpoint can be followed across scans.

Before a completed scan is stored, it is compared with the latest persisted scan for the same deterministic scope: resolved targets, enabled detectors, and relevant passive-integration settings. Material fingerprints exclude timestamps and latency-like evidence. The result contains new, changed, unchanged, and removed assets; storage retains each scan independently while preserving stable public asset IDs and `first_seen` timestamps. Cancelled or detector-degraded scans are retained for inspection but never become baselines or trigger delta alerts.
