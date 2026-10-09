# AgentSniff

AgentSniff is a Rust network scanner for discovering AI-agent infrastructure through passive observation, active probing, protocol detection, and signal fusion.

## Quick start

```bash
cargo install agentsniff --locked
agentsniff scan 192.168.1.0/24
agentsniff serve --port 9090
```

The source workspace is at repository top level. The legacy Python implementation is retired.

AgentPin documents are reported as unsigned discovery evidence until AgentSniff implements the protocol's cryptographic verification profile. Detection datasets are separately signed and verified against a pinned repository key.

The dashboard binds to `127.0.0.1` by default. Non-loopback binding requires a strong `AGENTSNIFF_API_TOKEN`, which authenticates every non-health route; use TLS for remote access.

## Guides

| Guide | Description |
|---|---|
| [Getting Started](getting-started.md) | Installation, verification, first scan, Docker |
| [Detectors](detectors.md) | Detection modules and confidence |
| [CLI Reference](cli-reference.md) | Commands and options |
| [Dashboard](dashboard.md) | Dashboard and streaming |
| [Configuration](configuration.md) | YAML and environment settings |
| [Alerting](alerting.md) | Webhook and SMTP alerts |
| [Integrations](integrations.md) | Zeek and nmap |
| [API Reference](api-reference.md) | REST and SSE endpoints |
| [Architecture](architecture.md) | Components and trust boundaries |
| [Wazuh](wazuh.md) | SIEM integration |
