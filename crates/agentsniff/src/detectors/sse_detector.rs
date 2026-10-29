use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};

use crate::config::ScanConfig;
use crate::ebpf::EbpfChannels;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// Compute the median of a mutable vector of f64 values.
/// Returns 0.0 for an empty vector.
pub fn compute_median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let len = values.len();
    if len % 2 == 1 {
        values[len / 2]
    } else {
        (values[len / 2 - 1] + values[len / 2]) / 2.0
    }
}

// ---------------------------------------------------------------------------
// Packet timing analysis
// ---------------------------------------------------------------------------

/// Packet timing analysis for SSE/LLM streaming pattern detection.
pub struct PacketTimingAnalysis {
    pub packet_count: usize,
    pub median_size: f64,
    pub median_inter_arrival_ms: f64,
}

impl PacketTimingAnalysis {
    /// Analyze packet metadata for SSE/LLM streaming patterns.
    /// Returns confidence score if pattern matches, None otherwise.
    pub fn analyze(&self) -> Option<f64> {
        // Need minimum 10 packets
        if self.packet_count < 10 {
            return None;
        }
        // Median size < 500 bytes (small token chunks)
        if self.median_size >= 500.0 {
            return None;
        }
        // Median inter-arrival 10-200ms (token generation cadence)
        if self.median_inter_arrival_ms < 10.0 || self.median_inter_arrival_ms > 200.0 {
            return None;
        }
        // Confidence: 0.5 + (packet_count / 100), clamped to 0.95
        let confidence = (0.5 + self.packet_count as f64 / 100.0).min(0.95);
        Some(confidence)
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

#[derive(Hash, PartialEq, Eq)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
}

#[derive(Default)]
struct FlowData {
    sizes: Vec<f64>,
    timestamps_ns: Vec<u64>,
}

#[derive(Default)]
struct FlowSamples {
    flows: HashMap<FlowKey, FlowData>,
    count: usize,
}

impl FlowSamples {
    fn record(&mut self, key: FlowKey, size: f64, timestamp: u64) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.count < 32_768,
            "SSE total sample budget exceeded; capture incomplete"
        );
        anyhow::ensure!(
            self.flows.contains_key(&key) || self.flows.len() < 1024,
            "SSE flow budget exceeded; capture incomplete"
        );
        let flow = self.flows.entry(key).or_default();
        anyhow::ensure!(
            flow.sizes.len() < 2048,
            "SSE per-flow sample budget exceeded; capture incomplete"
        );
        flow.sizes.push(size);
        flow.timestamps_ns.push(timestamp);
        self.count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SSE Detector
// ---------------------------------------------------------------------------

#[cfg(test)]
mod budget_tests {
    use super::*;
    fn key(n: u32) -> FlowKey {
        FlowKey {
            src: std::net::Ipv4Addr::from(n).into(),
            dst: "127.0.0.1".parse().unwrap(),
        }
    }
    #[test]
    fn bounds_individual_flows_and_aggregate_samples() {
        let mut samples = FlowSamples::default();
        for i in 0..2048 {
            samples.record(key(1), 100.0, i).unwrap();
        }
        assert!(samples.record(key(1), 100.0, 2048).is_err());
        let mut samples = FlowSamples::default();
        for i in 0..1024 {
            samples.record(key(i), 100.0, 1).unwrap();
        }
        assert!(samples.record(key(1024), 100.0, 1).is_err());
        let mut samples = FlowSamples::default();
        for i in 0..32768 {
            samples.record(key(i % 32), 100.0, i as u64).unwrap();
        }
        assert!(samples.record(key(0), 100.0, 1).is_err());
        assert_eq!(samples.count, 32768);
    }
}

/// SSE/LLM streaming detector.
///
/// Detects SSE streaming patterns by analyzing packet timing. Uses eBPF
/// passive mode when available, falls back to raw sockets.
pub struct SseDetector {
    #[allow(dead_code)]
    config: ScanConfig,
    signatures: SignatureData,
    ebpf_channels: Option<Arc<EbpfChannels>>,
}

impl SseDetector {
    /// Create a new SSE detector from scan configuration.
    pub fn new(config: &ScanConfig, ebpf_channels: Option<Arc<EbpfChannels>>) -> Self {
        Self {
            config: config.clone(),
            signatures: SignatureData::load_embedded(),
            ebpf_channels,
        }
    }

    /// Resolve LLM domains to IP addresses.
    async fn resolve_llm_ips(&self) -> HashSet<IpAddr> {
        let domains: Vec<String> = self
            .signatures
            .llm_domains
            .iter()
            .take(25)
            .cloned()
            .collect();

        let mut ips = HashSet::new();
        for domain in domains {
            let addr_str = format!("{domain}:443");
            match tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                addr_str.to_socket_addrs()
            })
            .await
            {
                Ok(Ok(addrs)) => {
                    for addr in addrs {
                        ips.insert(addr.ip());
                    }
                }
                _ => continue,
            }
        }
        ips
    }

    /// eBPF passive mode: subscribe to traffic events and analyze flows.
    async fn scan_ebpf(
        &self,
        targets: &[IpAddr],
        channels: &EbpfChannels,
    ) -> anyhow::Result<Vec<Signal>> {
        let mut rx = channels.traffic_tx.subscribe();
        let duration = std::time::Duration::from_secs(30);
        let deadline = tokio::time::Instant::now() + duration;

        let target_set: HashSet<IpAddr> = targets.iter().copied().collect();
        let llm_ips = self.resolve_llm_ips().await;

        let mut samples = FlowSamples::default();

        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Ok(event)) => {
                    let src_ip = IpAddr::V4(std::net::Ipv4Addr::from(event.src_addr));
                    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::from(event.dst_addr));

                    // Filter: one end must be a target, the other an LLM IP
                    let is_relevant = (target_set.contains(&src_ip) && llm_ips.contains(&dst_ip))
                        || (target_set.contains(&dst_ip) && llm_ips.contains(&src_ip));

                    if !is_relevant {
                        continue;
                    }

                    let key = FlowKey {
                        src: src_ip,
                        dst: dst_ip,
                    };
                    samples.record(key, event.pkt_len as f64, event.timestamp_ns)?;
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {
                    anyhow::bail!("SSE events dropped; capture incomplete")
                }
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
                Err(_) => break, // timeout
            }
        }

        self.analyze_flows(&samples.flows)
    }

    /// Raw socket fallback: capture packets for 30 seconds.
    async fn scan_raw_socket(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        let target_set: HashSet<IpAddr> = targets.iter().copied().collect();
        let llm_ips = self.resolve_llm_ips().await;

        let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(6))) {
            Ok(s) => s,
            Err(_) => return Ok(Vec::new()), // no root / no capability
        };
        socket.set_nonblocking(true)?;

        let duration = std::time::Duration::from_secs(30);
        let start = std::time::Instant::now();
        let mut samples = FlowSamples::default();
        let mut buf = [0u8; 65535];

        while start.elapsed() < duration {
            // A busy raw socket must still yield for cancellation.
            tokio::task::yield_now().await;
            // SAFETY: `buf` is a fully-initialized [u8; 65535] on the stack.
            // Casting to [MaybeUninit<u8>] is sound because MaybeUninit<u8> has
            // the same size and alignment as u8, and initialized memory is valid
            // MaybeUninit.
            let n = match socket.recv(unsafe {
                &mut *(&mut buf[..] as *mut [u8] as *mut [std::mem::MaybeUninit<u8>])
            }) {
                Ok(n) => n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Brief yield to avoid busy-spinning
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    continue;
                }
                Err(_) => break,
            };

            if n < 20 {
                continue; // too short for IPv4 header
            }

            // Parse IPv4 header
            let ihl = ((buf[0] & 0x0F) as usize) * 4;
            if ihl < 20 || n < ihl {
                continue;
            }
            let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
            let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

            // Check protocol is TCP (6)
            if buf[9] != 6 {
                continue;
            }

            // Filter: one end target, other LLM
            let is_relevant = (target_set.contains(&src_ip) && llm_ips.contains(&dst_ip))
                || (target_set.contains(&dst_ip) && llm_ips.contains(&src_ip));
            if !is_relevant {
                continue;
            }

            // Parse TCP header for data offset
            if n < ihl + 13 {
                continue;
            }
            let tcp_data_offset = ((buf[ihl + 12] >> 4) as usize) * 4;
            let payload_len = total_len.saturating_sub(ihl + tcp_data_offset);

            if payload_len == 0 {
                continue;
            }

            let key = FlowKey {
                src: src_ip,
                dst: dst_ip,
            };
            // Use monotonic clock since raw sockets don't give us kernel timestamps
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            samples.record(key, payload_len as f64, ts)?;
        }

        self.analyze_flows(&samples.flows)
    }

    /// Analyze collected flows and emit signals.
    fn analyze_flows(&self, flows: &HashMap<FlowKey, FlowData>) -> anyhow::Result<Vec<Signal>> {
        let mut signals = Vec::new();

        for (key, flow) in flows {
            if flow.sizes.len() < 10 {
                continue;
            }

            let mut sizes = flow.sizes.clone();
            let median_size = compute_median(&mut sizes);

            // Compute inter-arrival times in ms
            let mut inter_arrivals = Vec::new();
            let mut sorted_ts = flow.timestamps_ns.clone();
            sorted_ts.sort();
            for window in sorted_ts.windows(2) {
                let delta_ns = window[1].saturating_sub(window[0]);
                inter_arrivals.push(delta_ns as f64 / 1_000_000.0);
            }
            let median_iat = compute_median(&mut inter_arrivals);

            let analysis = PacketTimingAnalysis {
                packet_count: flow.sizes.len(),
                median_size,
                median_inter_arrival_ms: median_iat,
            };

            if let Some(confidence) = analysis.analyze() {
                let level = if confidence >= 0.8 {
                    Confidence::High
                } else if confidence >= 0.5 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };

                signals.push(Signal::new(
                    DetectorType::SseDetector,
                    "sse_streaming_detected".to_string(),
                    format!(
                        "SSE/LLM streaming pattern detected between {} and {} ({} packets, median size {:.0}B, median IAT {:.1}ms)",
                        key.src, key.dst, flow.sizes.len(), median_size, median_iat
                    ),
                    level,
                    serde_json::json!({
                        "src": key.src.to_string(),
                        "dst": key.dst.to_string(),
                        "packet_count": flow.sizes.len(),
                        "median_size": median_size,
                        "median_inter_arrival_ms": median_iat,
                        "confidence": confidence,
                    }),
                ));
            }
        }

        Ok(signals)
    }
}

#[async_trait]
impl Detector for SseDetector {
    fn name(&self) -> &str {
        "sse_detector"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::SseDetector
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        // Try eBPF passive mode first
        if let Some(ref channels) = self.ebpf_channels {
            let signals = self.scan_ebpf(targets, channels).await?;
            if !signals.is_empty() {
                return Ok(signals);
            }
        }

        // Fall back to raw socket capture
        self.scan_raw_socket(targets).await
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
