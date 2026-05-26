# Architecture

## Overview

```
┌──────────────────────────────────────────────────┐
│                 AgentSniff CLI                   │
│      scan │ serve │ init-config │ update-sigs    │
├──────────┬───────────────────────┬───────────────┤
│ REST API │    Scanner Engine     │  Web Dashboard│
│ FastAPI/ │                       │  (HTML/JS/CSS)│
│ Axum     │                       │  embedded     │
├──────────┴───────────┬───────────┴───────────────┤
│              Signal Correlator                   │
│     Groups signals by host, calculates scores    │
├─────┬─────┬─────┬─────┬─────┬─────┬─────┬────────┤
│ DNS │Port │Agent│ MCP │ EP  │ TLS │Traf.│  SSE   │
│ Mon │Scan │Pin  │ Det │Probe│ FP  │Anlz │  Det   │
├─────┴─────┴─────┴─────┴─────┴─────┴─────┴────────┤
│         Integrations (optional)                  │
│  Zeek DataSource │ nmap Enricher │ eBPF (v2)     │
├──────────────────────┴───────────────────────────┤
│              Target Network                      │
└──────────────────────────────────────────────────┘
```

v1 uses FastAPI + asyncio; v2 uses Axum + tokio. The dashboard HTML, signal/agent/scan-result JSON schemas, and on-disk SQLite schema are identical between the two so configuration, alert payloads, SARIF exports, and database history are interchangeable.

## Scan Pipeline

1. **Target resolution** — CIDR expanded to host IPs, DNS resolution
2. **Detector setup** — Each detector initializes (e.g., traffic analyzer resolves LLM API IPs)
3. **Concurrent detection** — All detectors run in parallel: `asyncio.create_task` on v1, `tokio::spawn` via a `JoinSet` on v2
4. **Signal correlation** — Signals grouped by host IP, agents enriched as signals arrive
5. **Fusion rules** — Cross-module rules applied (e.g., banner corroboration)
6. **nmap enrichment** (optional) — Post-scan service identification
7. **Result assembly** — Agents sorted by confidence, status assigned

## Signal Correlation

Signals from all detectors are grouped by source host IP. Each host with at least one signal becomes a `DetectedAgent`.

### Confidence Scoring

Confidence is calculated using **noisy-OR probability fusion**:

```
P = 1 - ∏(1 - p_i)
```

Where `p_i` is the confidence weight of each signal:

| Level | Weight |
|-------|--------|
| LOW | 0.2 |
| MEDIUM | 0.5 |
| HIGH | 0.8 |
| CONFIRMED | 1.0 |

Example: A host with one HIGH signal (0.8) and one MEDIUM signal (0.5) gets:

```
P = 1 - (1 - 0.8) × (1 - 0.5) = 1 - 0.1 = 0.90
```

### Status Assignment

| Score | Requirement | Status |
|-------|-------------|--------|
| >= 0.9 | At least one HIGH/CONFIRMED signal | VERIFIED |
| >= 0.5 | — | DETECTED |
| >= 0.2 | — | SUSPECTED |
| < 0.2 | — | (filtered out) |

## Fusion Rules

Cross-module rules that adjust confidence based on signal combinations:

- **Banner corroboration** — Port scanner banner matches an agent framework → boost port scanner signal from LOW to MEDIUM
- **nmap exclusion** — Non-agent service identified → downgrade to INFO (only if port scanner is the sole signal)
- **nmap boost** — Agent-like service confirmed → add corroborating NMAP_ENRICHER signal

## Integration Patterns

### DataSource (Zeek)

Replaces "how we observe" without changing "what we look for":

```
ZeekDataSource → load_traffic() → TrafficRecord list → TrafficAnalyzer
ZeekDataSource → load_dns()     → DnsRecord list     → DnsMonitor
ZeekDataSource → load_tls()     → TlsRecord list     → TlsFingerprint
```

### Enricher (nmap)

Post-processing step after detection and correlation:

```
Detectors → Signals → Correlation → Fusion → nmap Enricher → Final Result
```

## Storage Backends

v1 stores scan history in a single SQLite database at `~/.agentsniff/agentsniff.db`. v2 keeps SQLite as the default and adds two extra backends behind the same `StorageBackend` trait:

| Backend | v1 | v2 | Notes |
|---|:-:|:-:|---|
| SQLite (default) | ✓ | ✓ | Same on-disk schema |
| PostgreSQL | — | ✓ | `storage.backend: "postgres"` + `storage.postgres_url` |
| Redis | — | ✓ | `storage.backend: "redis"` + `storage.redis_url` |

## Key Files

### v1 (Python)

| File | Purpose |
|------|---------|
| `agentsniff/scanner.py` | Scan orchestrator, signal correlation |
| `agentsniff/fusion.py` | Cross-module fusion rules |
| `agentsniff/models.py` | Data models (DetectedAgent, DetectionSignal, ScanResult) |
| `agentsniff/config.py` | Configuration, known domains/ports/signatures |
| `agentsniff/server.py` | FastAPI REST API and SSE streaming |
| `agentsniff/storage.py` | SQLite persistence |
| `agentsniff/notifier.py` | Webhook and email alerting |
| `agentsniff/detectors/` | All eight detection modules |
| `agentsniff/integrations/` | Zeek and nmap integration |

### v2 (Rust)

| File | Purpose |
|------|---------|
| `agentsniff-rs/crates/agentsniff/src/scanner.rs` | Scan orchestrator + signal correlation |
| `agentsniff-rs/crates/agentsniff/src/fusion.rs` | Cross-module fusion rules |
| `agentsniff-rs/crates/agentsniff/src/models.rs` | Signal / DetectedAgent / ScanResult types |
| `agentsniff-rs/crates/agentsniff/src/config.rs` | ScanConfig + YAML / env loading |
| `agentsniff-rs/crates/agentsniff/src/server.rs` | Axum REST + SSE server |
| `agentsniff-rs/crates/agentsniff/src/storage*.rs` | SQLite, PostgreSQL, Redis backends |
| `agentsniff-rs/crates/agentsniff/src/notifier.rs` | Webhook + SMTP (lettre) alerting |
| `agentsniff-rs/crates/agentsniff/src/detectors/` | All eight detector modules |
| `agentsniff-rs/crates/agentsniff/src/integrations/` | Zeek + Nmap |
| `agentsniff-rs/crates/agentsniff/src/signatures/` | Embedded signed signature loader |
| `agentsniff-rs/crates/agentsniff-ebpf/` | Optional kernel eBPF programs (DNS, connect, TLS, traffic) |
| `agentsniff-rs/crates/agentsniff/assets/` | Embedded dashboard + signed signature files |

## ThirdKey Trust Stack

AgentSniff complements the ThirdKey trust infrastructure:

- [AgentPin](https://agentpin.org) — Cooperative agent discovery via cryptographic identity documents
- [SchemaPin](https://schemapin.org) — Verified tools detected on MCP servers can be cross-checked against SchemaPin signatures
- [Symbiont](https://symbiont.dev) — AgentSniff can run as a Symbiont agent with policy-enforced scanning boundaries
- [AgentNull](https://github.com/ThirdKeyAI/AgentNull) — Detection evasion research feeds back into scanner improvements
