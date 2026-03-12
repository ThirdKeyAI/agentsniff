//! eBPF subsystem loader and event-channel broker.
//!
//! Attempts to load pre-compiled eBPF object files and attach them to the
//! appropriate kernel hooks. When eBPF is not available (kernel support
//! missing, insufficient privileges, or programs not yet compiled) the
//! module degrades gracefully: callers receive [`EbpfStatus::unavailable`]
//! and channels that will simply never receive events.
//!
//! When compiled with `--features ebpf`, the full aya loader is included.
//! Without that feature, `try_load_ebpf` always returns unavailable status.

use std::sync::Arc;
use tokio::sync::broadcast;

use agentsniff_common::{ConnEvent, DnsEvent, TlsEvent, TrafficEvent};

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
    pub traffic_tx: broadcast::Sender<TrafficEvent>,
}

impl EbpfChannels {
    pub fn new() -> Self {
        let (dns_tx, _) = broadcast::channel(1024);
        let (conn_tx, _) = broadcast::channel(1024);
        let (tls_tx, _) = broadcast::channel(512);
        let (traffic_tx, _) = broadcast::channel(2048);
        Self {
            dns_tx,
            conn_tx,
            tls_tx,
            traffic_tx,
        }
    }
}

impl Default for EbpfChannels {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Loader — aya implementation (requires `ebpf` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "ebpf")]
mod loader {
    use super::*;
    use aya::maps::RingBuf;
    use aya::programs::{tc, KProbe, SchedClassifier, TcAttachType};

    macro_rules! ebpf_bytes {
        ($name:expr) => {
            include_bytes!(concat!(env!("OUT_DIR"), "/", $name))
        };
    }

    fn attach_tc(
        ebpf: &mut aya::Ebpf,
        prog_name: &str,
        interface: &str,
        attach_type: TcAttachType,
    ) -> EbpfProgramStatus {
        match (|| -> anyhow::Result<()> {
            let _ = tc::qdisc_add_clsact(interface); // ignore if already exists
            let prog: &mut SchedClassifier = ebpf
                .program_mut(prog_name)
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
            let prog: &mut KProbe = ebpf
                .program_mut(prog_name)
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

        // --- DNS capture ---
        let dns_status = match aya::Ebpf::load(ebpf_bytes!("dns")) {
            Ok(mut ebpf) => {
                let status =
                    attach_tc(&mut ebpf, "dns_egress", interface, TcAttachType::Egress);
                if matches!(status, EbpfProgramStatus::Attached) {
                    spawn_ringbuf_poller(&mut ebpf, "DNS_EVENTS", channels.dns_tx.clone());
                }
                std::mem::forget(ebpf);
                status
            }
            Err(e) => EbpfProgramStatus::Failed(format!("load: {e}")),
        };

        // --- Connection tracking ---
        let conn_status = match aya::Ebpf::load(ebpf_bytes!("connect")) {
            Ok(mut ebpf) => {
                let status =
                    attach_kprobe(&mut ebpf, "tcp_v4_connect", "tcp_v4_connect");
                if matches!(status, EbpfProgramStatus::Attached) {
                    spawn_ringbuf_poller(
                        &mut ebpf,
                        "CONN_EVENTS",
                        channels.conn_tx.clone(),
                    );
                }
                std::mem::forget(ebpf);
                status
            }
            Err(e) => EbpfProgramStatus::Failed(format!("load: {e}")),
        };

        // --- TLS capture ---
        let tls_status = match aya::Ebpf::load(ebpf_bytes!("tls")) {
            Ok(mut ebpf) => {
                let status =
                    attach_tc(&mut ebpf, "tls_egress", interface, TcAttachType::Egress);
                if matches!(status, EbpfProgramStatus::Attached) {
                    spawn_ringbuf_poller(
                        &mut ebpf,
                        "TLS_EVENTS",
                        channels.tls_tx.clone(),
                    );
                }
                std::mem::forget(ebpf);
                status
            }
            Err(e) => EbpfProgramStatus::Failed(format!("load: {e}")),
        };

        // --- Traffic timing ---
        let traffic_status = match aya::Ebpf::load(ebpf_bytes!("traffic")) {
            Ok(mut ebpf) => {
                let egress = attach_tc(
                    &mut ebpf,
                    "traffic_egress",
                    interface,
                    TcAttachType::Egress,
                );
                let ingress = attach_tc(
                    &mut ebpf,
                    "traffic_ingress",
                    interface,
                    TcAttachType::Ingress,
                );
                let status = match (&egress, &ingress) {
                    (EbpfProgramStatus::Attached, _)
                    | (_, EbpfProgramStatus::Attached) => {
                        spawn_ringbuf_poller(
                            &mut ebpf,
                            "TRAFFIC_EVENTS",
                            channels.traffic_tx.clone(),
                        );
                        EbpfProgramStatus::Attached
                    }
                    _ => EbpfProgramStatus::Failed(format!(
                        "egress: {egress}, ingress: {ingress}"
                    )),
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

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Attempt to load and attach all eBPF programs for `interface`.
///
/// Returns an [`EbpfStatus`] describing which programs loaded successfully
/// and an [`Arc<EbpfChannels>`] that callers can use to subscribe to events.
#[cfg(feature = "ebpf")]
pub fn try_load_ebpf(interface: &str) -> (EbpfStatus, Arc<EbpfChannels>) {
    loader::load_ebpf(interface)
}

/// Stub when eBPF feature is not compiled in.
#[cfg(not(feature = "ebpf"))]
pub fn try_load_ebpf(_interface: &str) -> (EbpfStatus, Arc<EbpfChannels>) {
    let channels = Arc::new(EbpfChannels::new());
    (EbpfStatus::unavailable(), channels)
}
