//! eBPF subsystem loader and event-channel broker.
//!
//! Attempts to load pre-compiled eBPF object files and attach them to the
//! appropriate kernel hooks. When eBPF is not available (kernel support
//! missing, insufficient privileges, or programs not yet compiled) the
//! module degrades gracefully: callers receive [`EbpfStatus::unavailable`]
//! and channels that will simply never receive events.
//!
//! Actual aya loading logic is deferred until the `agentsniff-ebpf` crate
//! can be compiled (requires nightly + bpf-linker). The stubs here keep
//! the rest of the codebase compilable on stable Rust in the meantime.

use std::sync::Arc;
use tokio::sync::broadcast;

use agentsniff_common::{ConnEvent, DnsEvent, TlsEvent};

// ---------------------------------------------------------------------------
// Status types
// ---------------------------------------------------------------------------

/// Status of an individual eBPF program.
#[derive(Debug, Clone)]
pub enum EbpfProgramStatus {
    /// Program was successfully compiled, loaded, and attached to its hook.
    Attached,
    /// Loading or attachment failed with a human-readable reason.
    Failed(String),
    /// eBPF is structurally unavailable in this build or environment.
    NotAvailable,
}

impl std::fmt::Display for EbpfProgramStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Attached => write!(f, "attached"),
            Self::Failed(reason) => write!(f, "failed: {reason}"),
            Self::NotAvailable => write!(f, "not available"),
        }
    }
}

/// Overall eBPF subsystem status — one entry per logical program.
#[derive(Debug, Clone)]
pub struct EbpfStatus {
    pub dns_capture: EbpfProgramStatus,
    pub conn_tracking: EbpfProgramStatus,
    pub tls_capture: EbpfProgramStatus,
    pub traffic_timing: EbpfProgramStatus,
}

impl EbpfStatus {
    /// Return a status where every program reports [`EbpfProgramStatus::NotAvailable`].
    pub fn unavailable() -> Self {
        Self {
            dns_capture: EbpfProgramStatus::NotAvailable,
            conn_tracking: EbpfProgramStatus::NotAvailable,
            tls_capture: EbpfProgramStatus::NotAvailable,
            traffic_timing: EbpfProgramStatus::NotAvailable,
        }
    }

    /// Print a human-readable startup summary to stdout.
    ///
    /// Example output:
    /// ```text
    /// eBPF DNS capture:     attached (eth0)
    /// eBPF conn tracking:   not available
    /// eBPF TLS capture:     not available
    /// eBPF traffic timing:  not available
    /// ```
    pub fn print_status(&self) {
        let check = |s: &EbpfProgramStatus| -> &'static str {
            match s {
                EbpfProgramStatus::Attached => "[ok]",
                EbpfProgramStatus::Failed(_) => "[fail]",
                EbpfProgramStatus::NotAvailable => "[n/a]",
            }
        };

        println!(
            "eBPF DNS capture:     {} {}",
            check(&self.dns_capture),
            self.dns_capture
        );
        println!(
            "eBPF conn tracking:   {} {}",
            check(&self.conn_tracking),
            self.conn_tracking
        );
        println!(
            "eBPF TLS capture:     {} {}",
            check(&self.tls_capture),
            self.tls_capture
        );
        println!(
            "eBPF traffic timing:  {} {}",
            check(&self.traffic_timing),
            self.traffic_timing
        );
    }
}

// ---------------------------------------------------------------------------
// Event channels
// ---------------------------------------------------------------------------

/// Broadcast channels that carry eBPF events to any number of detector tasks.
///
/// When eBPF is unavailable these channels are still created but will never
/// receive events; detectors that subscribe via [`broadcast::Receiver`] will
/// simply block (or be dropped) indefinitely without error.
pub struct EbpfChannels {
    pub dns_tx: broadcast::Sender<DnsEvent>,
    pub conn_tx: broadcast::Sender<ConnEvent>,
    pub tls_tx: broadcast::Sender<TlsEvent>,
}

impl EbpfChannels {
    /// Create channels with a reasonable buffer depth.
    pub fn new() -> Self {
        let (dns_tx, _) = broadcast::channel(1024);
        let (conn_tx, _) = broadcast::channel(1024);
        let (tls_tx, _) = broadcast::channel(1024);
        Self {
            dns_tx,
            conn_tx,
            tls_tx,
        }
    }
}

impl Default for EbpfChannels {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Loader entry point
// ---------------------------------------------------------------------------

/// Attempt to load and attach all eBPF programs for `interface`.
///
/// Returns an [`EbpfStatus`] describing which programs loaded successfully
/// and an [`Arc<EbpfChannels>`] that callers can use to subscribe to events.
///
/// # Current behaviour
///
/// Loading is not yet implemented — the compiled eBPF object files require
/// `bpf-linker` and a nightly toolchain that are not yet available in this
/// build environment.  The function always returns
/// [`EbpfStatus::unavailable`] and idle channels.  Actual aya loading,
/// ring-buffer polling tasks, and event forwarding will be added once the
/// `agentsniff-ebpf` crate can be compiled.
pub fn try_load_ebpf(_interface: &str) -> (EbpfStatus, Arc<EbpfChannels>) {
    let channels = Arc::new(EbpfChannels::new());

    // TODO: when bpf-linker is available:
    //   1. Include compiled ELF bytes via `include_bytes_aligned!`.
    //   2. Load with `aya::Ebpf::load(bytes)`.
    //   3. Attach TC programs to `_interface`.
    //   4. Attach kprobe `tcp_v4_connect`.
    //   5. Spawn tokio tasks to drain each `RingBuf` and forward events via
    //      `channels.{dns,conn,tls}_tx.send(event)`.
    //   6. Return `EbpfStatus` with `Attached` entries.

    let status = EbpfStatus::unavailable();
    (status, channels)
}
