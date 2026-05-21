# eBPF Implementation Design

**Date:** 2026-03-11
**Scope:** Full eBPF integration for agentsniff-rs — build toolchain, userspace loader, 4th kernel program, detector wiring

## Overview

Replace the stubbed eBPF loader with a working implementation using aya. When run with `--features ebpf` on nightly + bpf-linker, compiled eBPF programs are embedded in the binary. At runtime with appropriate privileges, they attach to a network interface and passively capture DNS queries, TCP connections, TLS ClientHellos, and packet timing — feeding data to detectors via broadcast channels.

## Build System

### Feature Gate

Add `ebpf` cargo feature to `agentsniff-rs/crates/agentsniff/Cargo.toml`:

```toml
[features]
default = []
ebpf = ["aya", "aya-log"]

[dependencies]
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }

[build-dependencies]
aya-build = { version = "0.1", optional = true }
```

### build.rs

When `ebpf` feature is active, use `aya-build` to compile the `agentsniff-ebpf` crate targeting `bpfel-unknown-none`. The compiled ELF is placed in `OUT_DIR` and embedded via `include_bytes_aligned!`.

Without the feature, `cargo build` works on stable Rust — no eBPF toolchain required.

### agentsniff-ebpf Crate

Already exists at `crates/agentsniff-ebpf/` with three programs (dns, connect, tls). Stays out of workspace members — compiled only by aya-build. Update its aya-ebpf dependency to match the userspace aya version.

## 4th eBPF Program: Traffic Timing

New file: `crates/agentsniff-ebpf/src/traffic.rs`

TC classifier on both ingress and egress. Captures packet metadata for timing analysis:

### Shared Struct (agentsniff-common)

```rust
#[repr(C)]
pub struct TrafficEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub pkt_len: u16,
    pub direction: u8,   // 0=egress, 1=ingress
    pub timestamp_ns: u64,
}
```

### Kernel Program

- Hook: TC classifier (ingress + egress)
- Filter: IPv4 TCP packets only
- Capture: IP header src/dst, TCP dst port, IP total length, direction flag
- Timestamp: `bpf_ktime_get_ns()`
- Output: RingBuf with capacity 2048 * sizeof(TrafficEvent)

## Timestamps

All four eBPF programs get real timestamps via `bpf_ktime_get_ns()` (currently hardcoded to 0).

## Userspace Loader (`ebpf.rs`)

### `try_load_ebpf(interface: &str) -> (EbpfStatus, Arc<EbpfChannels>)`

#### With `ebpf` feature:

1. **Validate interface** — return `NotAvailable` if interface is empty
2. **Load ELF** — `aya::Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/agentsniff-ebpf")))`
3. **Attach programs:**
   - `dns_capture` → TC egress on interface
   - `tls_capture` → TC egress on interface
   - `traffic_egress` → TC egress on interface
   - `traffic_ingress` → TC ingress on interface
   - `conn_track` → kprobe on `tcp_v4_connect`
4. **For each attached program's RingBuf map:**
   - Spawn a tokio task
   - Poll `RingBuf` with `AsyncFd` or periodic polling
   - Deserialize events from ring buffer entries
   - Send to corresponding `broadcast::Sender`
5. **Return** `EbpfStatus` with per-program `Attached`/`Failed` + `EbpfChannels`

#### Without `ebpf` feature:

Current behavior — return `NotAvailable` for all programs.

### EbpfChannels Update

Add 4th channel:

```rust
pub struct EbpfChannels {
    pub dns_tx: broadcast::Sender<DnsEvent>,
    pub conn_tx: broadcast::Sender<ConnEvent>,
    pub tls_tx: broadcast::Sender<TlsEvent>,
    pub traffic_tx: broadcast::Sender<TrafficEvent>,
}
```

## Detector Integration

### Pattern

Each detector that can use eBPF data gets an `Option<Arc<EbpfChannels>>` passed through the `ScanConfig` or at construction time. When channels are available, the detector subscribes to the relevant broadcast receiver and collects passive events during the scan window. Otherwise, it falls back to active probing.

### DnsMonitorDetector

- **eBPF mode:** Subscribe to `dns_rx`. For each `DnsEvent`, decode `query_name` and check against LLM domain lists and agent infra domain lists. Emit signals for matches.
- **Fallback mode:** Current behavior (forward/reverse DNS lookups on target IPs).

### TlsFingerprintDetector

- **eBPF mode:** Subscribe to `tls_rx`. For each `TlsEvent`, compute JA3 hash from `cipher_suites` and `extensions`. Match against known AI agent TLS fingerprints. Emit signals.
- **Fallback mode:** Current behavior (active TLS connection probing).

### TrafficAnalyzerDetector

- **eBPF mode:** Subscribe to `conn_rx` + `traffic_rx`. Analyze connection patterns and packet timing to detect bursty tool-calling behavior characteristic of AI agents. Emit signals.
- **Fallback mode:** Current behavior (`/proc/net/tcp` parsing).

### Channel Lifetime

- eBPF channels are created in `main.rs` before the scan loop
- Passed into the scanner, which passes them to detector constructors
- RingBuf polling tasks run for the lifetime of the server/scan process
- Detectors subscribe during `scan()` and collect events for the scan duration

## Plumbing: Config → Scanner → Detectors

1. `main.rs`: `let (ebpf_status, ebpf_channels) = try_load_ebpf(&config.ebpf_interface);`
2. Store `ebpf_channels` in `ScanConfig` or pass alongside it to `run_scan()`
3. `run_scan()` passes channels to detector constructors via registry
4. Each detector's `new()` accepts `Option<Arc<EbpfChannels>>`

## Error Handling

- Each program attaches independently — one failure doesn't block others
- `EbpfStatus` reports per-program status with failure reason
- If all programs fail, detectors silently fall back to active mode
- RingBuf overflow: events are dropped (kernel side), logged (userspace)

## Testing

- Existing tests continue to pass (no eBPF feature = no change)
- Unit tests for event deserialization and JA3 computation
- Integration tests for the loader require root — gated behind `#[cfg(feature = "ebpf")]` + `#[ignore]`
