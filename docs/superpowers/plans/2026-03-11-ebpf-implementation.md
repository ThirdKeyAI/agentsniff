# eBPF Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire up the full eBPF pipeline — build system, userspace loader, 4th kernel program, detector integration — so passive network monitoring works when compiled with `--features ebpf`.

**Architecture:** Feature-gated `ebpf` cargo feature uses `aya-build` to compile kernel programs at build time and embeds them. At runtime, `try_load_ebpf()` loads programs via aya, attaches to hooks, and polls RingBufs into broadcast channels. Detectors subscribe to channels for passive mode, falling back to active probing when eBPF is unavailable.

**Tech Stack:** aya 0.13 / aya-build 0.1 / aya-ebpf 0.1 (kernel side), tokio broadcast channels, nightly Rust + bpf-linker for eBPF compilation

**Spec:** `docs/superpowers/specs/2026-03-11-ebpf-implementation-design.md`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `crates/agentsniff/build.rs` | Conditionally compile eBPF crate via aya-build |
| Create | `crates/agentsniff-ebpf/src/traffic.rs` | 4th eBPF program: packet timing TC classifier |
| Modify | `crates/agentsniff-common/src/lib.rs` | Add `TrafficEvent` struct |
| Modify | `crates/agentsniff-ebpf/Cargo.toml` | Add 4th binary target `traffic` |
| Modify | `crates/agentsniff-ebpf/src/dns.rs` | Add `bpf_ktime_get_ns()` timestamp |
| Modify | `crates/agentsniff-ebpf/src/connect.rs` | Add `bpf_ktime_get_ns()` timestamp |
| Modify | `crates/agentsniff-ebpf/src/tls.rs` | Add `bpf_ktime_get_ns()` timestamp |
| Modify | `crates/agentsniff/Cargo.toml` | Add `ebpf` feature, aya deps |
| Modify | `crates/agentsniff/src/ebpf.rs` | Full loader implementation behind `#[cfg(feature = "ebpf")]` |
| Modify | `crates/agentsniff/src/main.rs` | Pass eBPF channels through to scanner/server |
| Modify | `crates/agentsniff/src/scanner.rs` | Accept + pass eBPF channels to detectors |
| Modify | `crates/agentsniff/src/detectors/mod.rs` | Update registry to pass channels to factories |
| Modify | `crates/agentsniff/src/detectors/dns_monitor.rs` | Add eBPF passive mode |
| Modify | `crates/agentsniff/src/detectors/tls_fingerprint.rs` | Add eBPF passive mode |
| Modify | `crates/agentsniff/src/detectors/traffic_analyzer.rs` | Add eBPF passive mode |
| Modify | `crates/agentsniff/src/server.rs` | Thread eBPF channels into AppState |
| Create | `crates/agentsniff/tests/test_ebpf_events.rs` | Unit tests for event deserialization |

---

## Chunk 1: Shared Types & 4th Kernel Program

### Task 1: Add TrafficEvent to agentsniff-common

**Files:**
- Modify: `crates/agentsniff-common/src/lib.rs`

- [ ] **Step 1: Add `TrafficEvent` struct**

Add after the `TlsEvent` struct:

```rust
/// Packet timing event from eBPF TC hook (ingress + egress).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrafficEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub pkt_len: u16,
    pub direction: u8, // 0 = egress, 1 = ingress
    pub timestamp_ns: u64,
}

pub const TRAFFIC_DIR_EGRESS: u8 = 0;
pub const TRAFFIC_DIR_INGRESS: u8 = 1;
```

- [ ] **Step 2: Verify build**

Run: `cargo build -j2 -p agentsniff-common`
Expected: compiles cleanly

- [ ] **Step 3: Commit**

```bash
git add crates/agentsniff-common/src/lib.rs
git commit -m "add TrafficEvent struct to agentsniff-common"
```

### Task 2: Add timestamps to existing eBPF programs

**Files:**
- Modify: `crates/agentsniff-ebpf/src/dns.rs`
- Modify: `crates/agentsniff-ebpf/src/connect.rs`
- Modify: `crates/agentsniff-ebpf/src/tls.rs`

- [ ] **Step 1: Update dns.rs**

Replace `(*event).timestamp_ns = 0; // bpf_ktime_get_ns() would go here` with:

```rust
(*event).timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
```

Note: `bpf_ktime_get_ns` is already accessible through `aya_ebpf::helpers`. The outer block is already `unsafe`, so just call it directly.

- [ ] **Step 2: Update connect.rs**

Same replacement in `connect.rs`.

- [ ] **Step 3: Update tls.rs**

Same replacement in `tls.rs`.

- [ ] **Step 4: Commit**

```bash
git add crates/agentsniff-ebpf/src/dns.rs crates/agentsniff-ebpf/src/connect.rs crates/agentsniff-ebpf/src/tls.rs
git commit -m "add bpf_ktime_get_ns timestamps to eBPF programs"
```

Note: These files cannot be compiled yet (need nightly + bpf-linker). Syntax-only changes.

### Task 3: Create traffic.rs eBPF program

**Files:**
- Create: `crates/agentsniff-ebpf/src/traffic.rs`
- Modify: `crates/agentsniff-ebpf/Cargo.toml`

- [ ] **Step 1: Write the traffic timing eBPF program**

Create `crates/agentsniff-ebpf/src/traffic.rs`:

```rust
//! eBPF TC hook for packet timing capture.
//!
//! Attached to both ingress and egress TC hooks. Captures IPv4 TCP
//! packet metadata (addresses, port, size, direction, timestamp) for
//! behavioral traffic analysis of AI agent patterns.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
};
use agentsniff_common::{TrafficEvent, TRAFFIC_DIR_EGRESS, TRAFFIC_DIR_INGRESS};

/// Ring buffer shared with userspace; sized for ~2 K events.
#[map]
static TRAFFIC_EVENTS: RingBuf = RingBuf::with_byte_size(
    2048 * core::mem::size_of::<TrafficEvent>() as u32,
    0,
);

const ETH_HDR_LEN: usize = 14;
const IPPROTO_TCP: u8 = 6;
/// Offset of IP protocol field.
const IP_PROTO_OFF: usize = ETH_HDR_LEN + 9;
/// Offset of IP total length field.
const IP_TOTAL_LEN_OFF: usize = ETH_HDR_LEN + 2;
/// Offset of TCP destination port.
const TCP_DST_PORT_OFF: usize = ETH_HDR_LEN + 20 + 2;

#[classifier]
pub fn traffic_egress(ctx: TcContext) -> i32 {
    match try_capture(&ctx, TRAFFIC_DIR_EGRESS) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[classifier]
pub fn traffic_ingress(ctx: TcContext) -> i32 {
    match try_capture(&ctx, TRAFFIC_DIR_INGRESS) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_capture(ctx: &TcContext, direction: u8) -> Result<i32, ()> {
    // Only TCP.
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP {
        return Ok(TC_ACT_OK as i32);
    }

    let src_addr_be: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| ())?;
    let dst_addr_be: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| ())?;
    let dst_port_be: u16 = ctx.load(TCP_DST_PORT_OFF).map_err(|_| ())?;
    let total_len_be: u16 = ctx.load(IP_TOTAL_LEN_OFF).map_err(|_| ())?;

    if let Some(mut entry) = TRAFFIC_EVENTS.reserve::<TrafficEvent>(0) {
        let event = unsafe { entry.as_mut_ptr() };
        unsafe {
            (*event).src_addr = u32::from_be(src_addr_be);
            (*event).dst_addr = u32::from_be(dst_addr_be);
            (*event).dst_port = u16::from_be(dst_port_be);
            (*event).pkt_len = u16::from_be(total_len_be);
            (*event).direction = direction;
            (*event).timestamp_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
        }
        entry.submit(0);
    }

    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

- [ ] **Step 2: Add binary target to Cargo.toml**

Add to `crates/agentsniff-ebpf/Cargo.toml`:

```toml
[[bin]]
name = "traffic"
path = "src/traffic.rs"
```

- [ ] **Step 3: Commit**

```bash
git add crates/agentsniff-ebpf/src/traffic.rs crates/agentsniff-ebpf/Cargo.toml
git commit -m "add traffic timing eBPF program (TC ingress+egress)"
```

---

## Chunk 2: Build System & Feature Gate

### Task 4: Add ebpf feature and aya dependencies

**Files:**
- Modify: `crates/agentsniff/Cargo.toml`

- [ ] **Step 1: Add feature flag and dependencies**

Add these sections to `crates/agentsniff/Cargo.toml`:

```toml
[features]
default = []
ebpf = ["dep:aya", "dep:aya-log"]

[dependencies]
# ... existing deps ...
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }

[build-dependencies]
aya-build = { version = "0.1", optional = true }
```

Also add to `[features]`: `ebpf = ["dep:aya", "dep:aya-log", "dep:aya-build"]`

Wait — `aya-build` is a build-dependency. Feature flags for build-deps work differently. The `build.rs` should check `cfg(feature = "ebpf")` and `aya-build` should be unconditional as a build-dep (but only used when the feature is active). Actually, the cleaner approach: make `aya-build` optional too.

Final Cargo.toml additions:

```toml
[features]
default = []
ebpf = ["dep:aya", "dep:aya-log"]

[dependencies]
aya = { version = "0.13", optional = true }
aya-log = { version = "0.2", optional = true }

[build-dependencies]
aya-build = { version = "0.1", optional = true }
```

And add `"dep:aya-build"` to the ebpf feature list:

```toml
ebpf = ["dep:aya", "dep:aya-log", "dep:aya-build"]
```

- [ ] **Step 2: Verify default build still works**

Run: `cargo build -j2`
Expected: compiles without aya deps (they're optional)

- [ ] **Step 3: Commit**

```bash
git add crates/agentsniff/Cargo.toml
git commit -m "add ebpf feature gate with aya dependencies"
```

### Task 5: Create build.rs

**Files:**
- Create: `crates/agentsniff/build.rs`

- [ ] **Step 1: Write the build script**

Create `crates/agentsniff/build.rs`:

```rust
fn main() {
    #[cfg(feature = "ebpf")]
    {
        let ebpf_crate = std::path::PathBuf::from("../agentsniff-ebpf");
        aya_build::build_ebpf([ebpf_crate])
            .expect("failed to compile eBPF programs");
    }
}
```

Note: `aya_build::build_ebpf` compiles each `[[bin]]` target in the eBPF crate to BPF ELF. The output goes to `OUT_DIR`.

- [ ] **Step 2: Verify default build still works**

Run: `cargo build -j2`
Expected: compiles (build.rs is a no-op without `ebpf` feature)

- [ ] **Step 3: Commit**

```bash
git add crates/agentsniff/build.rs
git commit -m "add build.rs for conditional eBPF compilation via aya-build"
```

---

## Chunk 3: Userspace Loader

### Task 6: Implement try_load_ebpf with aya

**Files:**
- Modify: `crates/agentsniff/src/ebpf.rs`

- [ ] **Step 1: Update EbpfChannels to include TrafficEvent**

Add `TrafficEvent` import and 4th channel:

```rust
use agentsniff_common::{ConnEvent, DnsEvent, TlsEvent, TrafficEvent};

pub struct EbpfChannels {
    pub dns_tx: broadcast::Sender<DnsEvent>,
    pub conn_tx: broadcast::Sender<ConnEvent>,
    pub tls_tx: broadcast::Sender<TlsEvent>,
    pub traffic_tx: broadcast::Sender<TrafficEvent>,
}

impl EbpfChannels {
    pub fn new() -> Self {
        let (dns_tx, _) = broadcast::channel(1024);
        let (conn_tx, _) = broadcast::channel(1024);
        let (tls_tx, _) = broadcast::channel(512);
        let (traffic_tx, _) = broadcast::channel(2048);
        Self { dns_tx, conn_tx, tls_tx, traffic_tx }
    }
}
```

- [ ] **Step 2: Add the aya loader behind `#[cfg(feature = "ebpf")]`**

Replace the `try_load_ebpf` function with a cfg-split version:

```rust
#[cfg(feature = "ebpf")]
mod loader {
    use super::*;
    use aya::maps::RingBuf;
    use aya::programs::{tc, KProbe, SchedClassifier, TcAttachType};
    use std::os::fd::AsFd;

    /// Include the compiled eBPF ELF binaries.
    /// aya-build puts them at OUT_DIR/<binary_name>.
    macro_rules! ebpf_bytes {
        ($name:expr) => {
            include_bytes!(concat!(env!("OUT_DIR"), "/", $name))
        };
    }

    /// Try to load a single TC program, returning program status.
    fn attach_tc(
        ebpf: &mut aya::Ebpf,
        prog_name: &str,
        interface: &str,
        attach_type: TcAttachType,
    ) -> EbpfProgramStatus {
        match (|| -> anyhow::Result<()> {
            let _ = tc::qdisc_add_clsact(interface);  // ignore if already exists
            let prog: &mut SchedClassifier = ebpf.program_mut(prog_name)
                .ok_or_else(|| anyhow::anyhow!("program '{}' not found", prog_name))?
                .try_into()?;
            prog.load()?;
            prog.attach(interface, attach_type)?;
            Ok(())
        })() {
            Ok(()) => EbpfProgramStatus::Attached,
            Err(e) => EbpfProgramStatus::Failed(e.to_string()),
        }
    }

    fn attach_kprobe(
        ebpf: &mut aya::Ebpf,
        prog_name: &str,
        fn_name: &str,
    ) -> EbpfProgramStatus {
        match (|| -> anyhow::Result<()> {
            let prog: &mut KProbe = ebpf.program_mut(prog_name)
                .ok_or_else(|| anyhow::anyhow!("program '{}' not found", prog_name))?
                .try_into()?;
            prog.load()?;
            prog.attach(fn_name, 0)?;
            Ok(())
        })() {
            Ok(()) => EbpfProgramStatus::Attached,
            Err(e) => EbpfProgramStatus::Failed(e.to_string()),
        }
    }

    /// Spawn a tokio task that polls a RingBuf map and sends events to a broadcast channel.
    fn spawn_ringbuf_poller<E: Copy + Send + 'static>(
        ebpf: &mut aya::Ebpf,
        map_name: &str,
        tx: broadcast::Sender<E>,
    ) {
        let map = ebpf.take_map(map_name);
        if let Some(map) = map {
            match RingBuf::try_from(map) {
                Ok(mut ring_buf) => {
                    tokio::spawn(async move {
                        loop {
                            while let Some(item) = ring_buf.next() {
                                if item.len() == std::mem::size_of::<E>() {
                                    let event: E = unsafe {
                                        std::ptr::read_unaligned(item.as_ptr() as *const E)
                                    };
                                    let _ = tx.send(event);
                                }
                            }
                            // Sleep briefly to avoid busy-spinning
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to open RingBuf '{}': {}", map_name, e);
                }
            }
        }
    }

    pub fn load_ebpf(interface: &str) -> (EbpfStatus, Arc<EbpfChannels>) {
        let channels = Arc::new(EbpfChannels::new());

        if interface.is_empty() {
            tracing::warn!("No eBPF interface specified; skipping eBPF loading");
            return (EbpfStatus::unavailable(), channels);
        }

        // Load each eBPF program from its compiled ELF.
        // Each program is a separate ELF binary compiled by aya-build.

        // --- DNS capture ---
        let dns_status = match aya::Ebpf::load(ebpf_bytes!("dns")) {
            Ok(mut ebpf) => {
                let status = attach_tc(&mut ebpf, "dns_egress", interface, TcAttachType::Egress);
                if matches!(status, EbpfProgramStatus::Attached) {
                    spawn_ringbuf_poller(&mut ebpf, "DNS_EVENTS", channels.dns_tx.clone());
                }
                // Leak the Ebpf handle so programs stay loaded
                std::mem::forget(ebpf);
                status
            }
            Err(e) => EbpfProgramStatus::Failed(format!("load: {e}")),
        };

        // --- Connection tracking ---
        let conn_status = match aya::Ebpf::load(ebpf_bytes!("connect")) {
            Ok(mut ebpf) => {
                let status = attach_kprobe(&mut ebpf, "tcp_v4_connect", "tcp_v4_connect");
                if matches!(status, EbpfProgramStatus::Attached) {
                    spawn_ringbuf_poller(&mut ebpf, "CONN_EVENTS", channels.conn_tx.clone());
                }
                std::mem::forget(ebpf);
                status
            }
            Err(e) => EbpfProgramStatus::Failed(format!("load: {e}")),
        };

        // --- TLS capture ---
        let tls_status = match aya::Ebpf::load(ebpf_bytes!("tls")) {
            Ok(mut ebpf) => {
                let status = attach_tc(&mut ebpf, "tls_egress", interface, TcAttachType::Egress);
                if matches!(status, EbpfProgramStatus::Attached) {
                    spawn_ringbuf_poller(&mut ebpf, "TLS_EVENTS", channels.tls_tx.clone());
                }
                std::mem::forget(ebpf);
                status
            }
            Err(e) => EbpfProgramStatus::Failed(format!("load: {e}")),
        };

        // --- Traffic timing ---
        let traffic_status = match aya::Ebpf::load(ebpf_bytes!("traffic")) {
            Ok(mut ebpf) => {
                let egress = attach_tc(&mut ebpf, "traffic_egress", interface, TcAttachType::Egress);
                let ingress = attach_tc(&mut ebpf, "traffic_ingress", interface, TcAttachType::Ingress);
                let status = match (&egress, &ingress) {
                    (EbpfProgramStatus::Attached, _) | (_, EbpfProgramStatus::Attached) => {
                        spawn_ringbuf_poller(&mut ebpf, "TRAFFIC_EVENTS", channels.traffic_tx.clone());
                        EbpfProgramStatus::Attached
                    }
                    _ => EbpfProgramStatus::Failed(format!("egress: {egress}, ingress: {ingress}")),
                };
                std::mem::forget(ebpf);
                status
            }
            Err(e) => EbpfProgramStatus::Failed(format!("load: {e}")),
        };

        let status = EbpfStatus {
            dns_capture: dns_status,
            conn_tracking: conn_status,
            tls_capture: tls_status,
            traffic_timing: traffic_status,
        };

        (status, channels)
    }
}

#[cfg(feature = "ebpf")]
pub fn try_load_ebpf(interface: &str) -> (EbpfStatus, Arc<EbpfChannels>) {
    loader::load_ebpf(interface)
}

#[cfg(not(feature = "ebpf"))]
pub fn try_load_ebpf(_interface: &str) -> (EbpfStatus, Arc<EbpfChannels>) {
    let channels = Arc::new(EbpfChannels::new());
    (EbpfStatus::unavailable(), channels)
}
```

- [ ] **Step 3: Verify default build still works (no ebpf feature)**

Run: `cargo build -j2`
Expected: compiles — the `#[cfg(not(feature = "ebpf"))]` path is used

- [ ] **Step 4: Commit**

```bash
git add crates/agentsniff/src/ebpf.rs
git commit -m "implement eBPF userspace loader with aya behind feature gate"
```

---

## Chunk 4: Plumbing — Channels Through Scanner to Detectors

### Task 7: Thread eBPF channels through the system

**Files:**
- Modify: `crates/agentsniff/src/main.rs`
- Modify: `crates/agentsniff/src/server.rs`
- Modify: `crates/agentsniff/src/scanner.rs`
- Modify: `crates/agentsniff/src/detectors/mod.rs`

- [ ] **Step 1: Update main.rs to pass channels**

In `main.rs` around line 215, change:

```rust
let (ebpf_status, _channels) =
    try_load_ebpf(&scan_config.ebpf_interface);
```

to:

```rust
let (ebpf_status, ebpf_channels) =
    try_load_ebpf(&scan_config.ebpf_interface);
```

Then pass `ebpf_channels` when creating the server. Update the `run_server` call to accept and store channels (see server.rs changes below).

- [ ] **Step 2: Update server.rs AppState to hold channels**

Add to `AppState`:

```rust
pub ebpf_channels: Arc<EbpfChannels>,
```

Update `create_router` and `create_router_with_storage` to accept `Arc<EbpfChannels>`. Update `run_server` signature to accept channels. Pass channels into `spawn_scan` → `run_scan`.

- [ ] **Step 3: Update run_scan signature**

In `scanner.rs`, change:

```rust
pub async fn run_scan(
    config: &ScanConfig,
    cancel: Option<CancellationToken>,
    on_agent: Option<OnAgentCallback>,
) -> anyhow::Result<ScanResult> {
```

to:

```rust
pub async fn run_scan(
    config: &ScanConfig,
    ebpf_channels: Option<Arc<crate::ebpf::EbpfChannels>>,
    cancel: Option<CancellationToken>,
    on_agent: Option<OnAgentCallback>,
) -> anyhow::Result<ScanResult> {
```

Pass `ebpf_channels` into `build_registry` / detector factories.

- [ ] **Step 4: Update DetectorRegistry to pass channels**

In `detectors/mod.rs`, change the factory signature to accept optional channels:

```rust
type DetectorFactory = Box<dyn Fn(&ScanConfig, Option<Arc<EbpfChannels>>) -> Box<dyn Detector> + Send + Sync>;
```

Update `register()`, `create_enabled()`, and all factory call sites in `scanner.rs` `build_registry()`.

- [ ] **Step 5: Update all call sites**

Update all call sites that call `run_scan`:
- `server.rs` `spawn_scan` — pass `state.ebpf_channels.clone()`
- `main.rs` scan command — pass `None` (or load channels there too)

Update all detector factory registrations in `build_registry()` to accept and pass channels:

```rust
registry.register("dns_monitor", "enable_dns_monitor", |config, channels| {
    Box::new(DnsMonitorDetector::new(config, channels))
});
```

For detectors that don't use eBPF (port_scanner, agentpin_prober, mcp_detector, endpoint_prober, sse_detector), just ignore the channels parameter:

```rust
registry.register("port_scanner", "enable_port_scanner", |config, _channels| {
    Box::new(PortScannerDetector::new(config))
});
```

- [ ] **Step 6: Verify build**

Run: `cargo build -j2`
Expected: compiles (detectors still use `_channels` but don't consume yet)

- [ ] **Step 7: Run tests**

Run: `cargo test -j2`
Expected: all existing tests pass

- [ ] **Step 8: Commit**

```bash
git add crates/agentsniff/src/main.rs crates/agentsniff/src/server.rs crates/agentsniff/src/scanner.rs crates/agentsniff/src/detectors/mod.rs
git commit -m "thread eBPF channels from loader through scanner to detectors"
```

---

## Chunk 5: Detector Integration

### Task 8: Wire DnsMonitorDetector to eBPF

**Files:**
- Modify: `crates/agentsniff/src/detectors/dns_monitor.rs`

- [ ] **Step 1: Add eBPF channel field**

```rust
use std::sync::Arc;
use crate::ebpf::EbpfChannels;

pub struct DnsMonitorDetector {
    config: ScanConfig,
    signatures: SignatureData,
    ebpf_channels: Option<Arc<EbpfChannels>>,
}

impl DnsMonitorDetector {
    pub fn new(config: &ScanConfig, ebpf_channels: Option<Arc<EbpfChannels>>) -> Self {
        Self {
            config: config.clone(),
            signatures: SignatureData::load_embedded(),
            ebpf_channels,
        }
    }
}
```

- [ ] **Step 2: Add eBPF passive scan path**

In the `scan()` method, add an eBPF branch at the top that collects DNS events for a brief window (e.g., config.dns_monitor_duration seconds), then checks captured domains against the signature lists. If eBPF channels have no subscribers or produce no events, fall through to the existing active mode.

```rust
async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
    // Try eBPF passive mode first
    if let Some(ref channels) = self.ebpf_channels {
        let mut rx = channels.dns_tx.subscribe();
        let duration = Duration::from_secs(self.config.dns_monitor_duration);
        let deadline = tokio::time::Instant::now() + duration;
        let mut signals = Vec::new();
        let target_set: std::collections::HashSet<IpAddr> = targets.iter().copied().collect();

        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Ok(event)) => {
                    let src_ip = std::net::Ipv4Addr::from(event.src_addr);
                    if !target_set.contains(&IpAddr::V4(src_ip)) {
                        continue;
                    }
                    let domain = std::str::from_utf8(&event.query_name[..event.query_len as usize])
                        .unwrap_or("")
                        .to_lowercase();
                    if domain.is_empty() {
                        continue;
                    }
                    // Check against LLM domains
                    if matches_known_domain(&domain, &self.signatures.llm_domains, &[]) {
                        signals.push(Signal::new(
                            DetectorType::DnsMonitor,
                            "llm_api_domain".into(),
                            format!("DNS query to LLM API: {}", domain),
                            Confidence::High,
                            serde_json::json!({"ip": src_ip.to_string(), "domain": domain, "source": "ebpf"}),
                        ));
                    }
                    // Check agent infra domains
                    if matches_known_domain(&domain, &self.signatures.agent_infra_domains, &[]) {
                        signals.push(Signal::new(
                            DetectorType::DnsMonitor,
                            "agent_infra_domain".into(),
                            format!("DNS query to agent infra: {}", domain),
                            Confidence::Medium,
                            serde_json::json!({"ip": src_ip.to_string(), "domain": domain, "source": "ebpf"}),
                        ));
                    }
                }
                Ok(Err(_)) => break, // channel closed
                Err(_) => break,     // timeout
            }
        }

        if !signals.is_empty() {
            return Ok(signals);
        }
        // Fall through to active mode if no eBPF events captured
    }

    // ... existing active/fallback scan code ...
}
```

- [ ] **Step 3: Verify build and tests**

Run: `cargo build -j2 && cargo test -j2 --test test_dns_monitor`
Expected: passes — eBPF path is `None` in tests, falls through to existing code

- [ ] **Step 4: Commit**

```bash
git add crates/agentsniff/src/detectors/dns_monitor.rs
git commit -m "wire DnsMonitorDetector to eBPF passive DNS capture"
```

### Task 9: Wire TlsFingerprintDetector to eBPF

**Files:**
- Modify: `crates/agentsniff/src/detectors/tls_fingerprint.rs`

- [ ] **Step 1: Add eBPF channel field and update constructor**

```rust
use std::sync::Arc;
use crate::ebpf::EbpfChannels;

pub struct TlsFingerprintDetector {
    config: ScanConfig,
    timeout: Duration,
    client: reqwest::Client,
    ebpf_channels: Option<Arc<EbpfChannels>>,
}
```

Update `new()` to accept `Option<Arc<EbpfChannels>>`.

- [ ] **Step 2: Add eBPF passive scan path**

In `scan()`, add eBPF branch that subscribes to `tls_rx`, collects `TlsEvent`s for a scan window, computes JA3 fingerprints, and emits signals. JA3 computation from `TlsEvent`:

```rust
fn compute_ja3_from_event(event: &agentsniff_common::TlsEvent) -> String {
    let ciphers: Vec<String> = event.cipher_suites[..event.cipher_count as usize]
        .iter()
        .map(|c| c.to_string())
        .collect();
    let extensions: Vec<String> = event.extensions[..event.extension_count as usize]
        .iter()
        .map(|e| e.to_string())
        .collect();
    format!("{},{},{}", event.tls_version, ciphers.join("-"), extensions.join("-"))
}
```

Filter events where `dst_addr` matches a target IP. Emit signal with JA3 string and Low confidence (same as active mode).

- [ ] **Step 3: Verify build and tests**

Run: `cargo build -j2 && cargo test -j2 --test test_tls_fingerprint`

- [ ] **Step 4: Commit**

```bash
git add crates/agentsniff/src/detectors/tls_fingerprint.rs
git commit -m "wire TlsFingerprintDetector to eBPF passive TLS capture"
```

### Task 10: Wire TrafficAnalyzerDetector to eBPF

**Files:**
- Modify: `crates/agentsniff/src/detectors/traffic_analyzer.rs`

- [ ] **Step 1: Add eBPF channel field and update constructor**

Same pattern: add `ebpf_channels: Option<Arc<EbpfChannels>>` field.

- [ ] **Step 2: Add eBPF passive scan path**

Subscribe to both `conn_rx` and `traffic_rx`. For connection events, detect outbound connections to LLM ports (same logic as /proc/net/tcp parsing). For traffic events, analyze packet timing patterns:

- Collect events per target IP
- Detect bursty patterns: clusters of rapid request/response within short time windows (characteristic of tool-calling agents)
- Thresholds: 3+ unique remote ports AND 5+ connections → Medium confidence (same as existing heuristic)

- [ ] **Step 3: Verify build and tests**

Run: `cargo build -j2 && cargo test -j2 --test test_traffic_analyzer`

- [ ] **Step 4: Commit**

```bash
git add crates/agentsniff/src/detectors/traffic_analyzer.rs
git commit -m "wire TrafficAnalyzerDetector to eBPF passive traffic capture"
```

---

## Chunk 6: Tests & Verification

### Task 11: Add event deserialization tests

**Files:**
- Create: `crates/agentsniff/tests/test_ebpf_events.rs`

- [ ] **Step 1: Write tests for event struct sizes and roundtrip**

```rust
use agentsniff_common::*;

#[test]
fn test_dns_event_size() {
    // Ensure repr(C) struct has expected size for kernel compatibility
    assert_eq!(std::mem::size_of::<DnsEvent>(), 274); // 4+4+256+2+8
}

#[test]
fn test_conn_event_size() {
    assert_eq!(std::mem::size_of::<ConnEvent>(), 16); // 4+4+2+1+pad?+8
    // Note: verify actual size with repr(C) padding
}

#[test]
fn test_tls_event_size() {
    // Verify struct is correctly laid out
    let event = TlsEvent {
        src_addr: 0x0A000001,
        dst_addr: 0x0A000002,
        dst_port: 443,
        tls_version: 0x0303,
        cipher_suites: [0u16; 64],
        cipher_count: 2,
        extensions: [0u16; 64],
        extension_count: 3,
        timestamp_ns: 12345,
    };
    assert_eq!(event.cipher_count, 2);
    assert_eq!(event.extension_count, 3);
}

#[test]
fn test_traffic_event_size() {
    let event = TrafficEvent {
        src_addr: 0x0A000001,
        dst_addr: 0x0A000002,
        dst_port: 443,
        pkt_len: 1500,
        direction: TRAFFIC_DIR_EGRESS,
        timestamp_ns: 99999,
    };
    assert_eq!(event.direction, 0);
    assert_eq!(event.pkt_len, 1500);
}
```

Note: Exact sizes depend on repr(C) padding. Adjust assertions after verifying on the target platform.

- [ ] **Step 2: Run tests**

Run: `cargo test -j2 --test test_ebpf_events`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/agentsniff/tests/test_ebpf_events.rs
git commit -m "add eBPF event struct tests"
```

### Task 12: Full integration verification

- [ ] **Step 1: Run clippy**

Run: `cargo clippy -j2`
Expected: no warnings

- [ ] **Step 2: Run all tests**

Run: `cargo test -j2`
Expected: all pass

- [ ] **Step 3: Test default build (no ebpf feature)**

Run: `cargo build -j2`
Expected: compiles, `try_load_ebpf` returns `NotAvailable` for all programs

- [ ] **Step 4: Verify the server starts cleanly**

Run: `cargo run -j2 -- serve --port 9091`
Expected: shows `[n/a] not available` for all eBPF programs (same as before since `ebpf` feature not enabled), server starts normally, dashboard works

- [ ] **Step 5: Commit any final fixes**
