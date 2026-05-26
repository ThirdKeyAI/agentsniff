# Getting Started

## Installation — v1 (Python)

### PyPI

```bash
pip install agentsniff
```

### With nmap integration

```bash
pip install agentsniff[nmap]
```

### From source

```bash
git clone https://github.com/ThirdKeyAI/agentsniff.git
cd agentsniff
pip install -e .
```

### Docker

```bash
docker build -t agentsniff .

# Web dashboard (host network for full visibility)
docker run -d --name agentsniff \
  --network host \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  agentsniff

# One-shot scan
docker run --rm --network host --cap-add NET_RAW \
  agentsniff scan 192.168.1.0/24
```

### Docker Compose

```bash
docker compose up -d
# Dashboard at http://localhost:9090
```

## Installation — v2 (Rust)

### crates.io

```bash
cargo install agentsniff

# With eBPF passive capture (nightly toolchain auto-selected by the inner crate)
cargo install agentsniff --features ebpf
```

### From source

```bash
git clone https://github.com/ThirdKeyAI/agentsniff.git
cd agentsniff/agentsniff-rs

# Standard build — binary at ./target/release/agentsniff
cargo build --release

# With optional eBPF passive capture (requires a nightly toolchain)
cargo build --release --features ebpf
```

The Rust binary is self-contained: it statically embeds the dashboard HTML and the signed signature files. Drop the single `agentsniff` executable anywhere and run it.

To pull in the optional Zeek and Nmap integrations, just have `nmap` on `$PATH` and point `--zeek-logs` at a Zeek JSON log directory — no extra build flags needed.

## Requirements

**v1 (Python)**
- Python 3.11+
- Linux recommended (for `/proc/net/tcp` analysis)
- Root/CAP_NET_RAW optional (enables passive DNS, TLS, and traffic monitoring)

**v2 (Rust)**
- Rust 1.75+ (stable) — the userspace workspace pins `stable` via `rust-toolchain.toml`
- Linux recommended; `--features ebpf` requires a nightly toolchain and a recent kernel (the embedded eBPF crate pins nightly itself, so `cargo install agentsniff --features ebpf` selects it automatically as long as nightly is installed)
- Root/CAP_NET_RAW optional (same passive-capture trade-off as v1)
- Optional external integrations: `nmap` binary on `$PATH` for `--nmap`, Zeek log directory for `--zeek-logs`

## Your First Scan

The CLI is identical on both v1 and v2. Use `agentsniff` (v1) or the path to the Rust binary (`./target/release/agentsniff` for v2).

Scan a single host:

```bash
agentsniff scan 192.168.1.100/32
```

Scan a subnet:

```bash
agentsniff scan 192.168.1.0/24
```

Scan specific hosts:

```bash
agentsniff scan --hosts server1,server2,server3
```

## Output Formats

```bash
# Table (default) — human-readable terminal output
agentsniff scan 192.168.1.0/24

# JSON — machine-readable
agentsniff scan 192.168.1.0/24 --format json --output results.json

# CSV — spreadsheet-friendly
agentsniff scan 192.168.1.0/24 --format csv --output results.csv
```

## Web Dashboard

Start the dashboard and open it in your browser:

```bash
agentsniff serve --port 9090
# Open http://localhost:9090
```

The dashboard provides real-time scan streaming, scan history, and settings management. See the [Dashboard](dashboard.md) guide for details.

## What Gets Detected

AgentSniff identifies:

- AI agent frameworks (LangChain, CrewAI, AutoGen, Dify, Flowise, n8n, and 50+ more)
- MCP (Model Context Protocol) servers
- LLM inference engines (Ollama, LM Studio, vLLM)
- Hosts querying LLM API domains (OpenAI, Anthropic, Google, Mistral, etc.)
- AgentPin identity documents
- Agent-like network traffic patterns

Each detection gets a confidence score from LOW to CONFIRMED, calculated using noisy-OR probability fusion across all detectors that produced signals for a given host.
