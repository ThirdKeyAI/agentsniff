use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::config::ScanConfig;
use crate::ebpf::EbpfChannels;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

/// Ports commonly used by LLM APIs.
const LLM_API_PORTS: &[u16] = &[443, 8080, 11434, 3000];

/// TCP state for ESTABLISHED connections in /proc/net/tcp.
const TCP_ESTABLISHED: u8 = 1;

/// Traffic analyzer detector.
///
/// When eBPF channels are available, operates in passive mode by subscribing
/// to connection and traffic timing events from the kernel. Falls back to
/// reading `/proc/net/tcp` when eBPF is unavailable.
///
/// In `/proc/net/tcp` mode the detector mirrors the Python implementation: it
/// resolves the embedded LLM API domain list to a set of IPs and only emits
/// signals for connections to those IPs on port 443. The signal is attributed
/// to the local end of the connection (the host actually making the LLM
/// call) — not to whichever target the scanner happens to be probing — so
/// active probing against an unrelated host does not produce phantom traffic
/// signals.
pub struct TrafficAnalyzerDetector {
    #[allow(dead_code)]
    config: ScanConfig,
    signatures: SignatureData,
    ebpf_channels: Option<Arc<EbpfChannels>>,
    llm_ips: std::sync::Mutex<std::collections::HashSet<IpAddr>>,
}

impl TrafficAnalyzerDetector {
    pub fn new(config: &ScanConfig, ebpf_channels: Option<Arc<EbpfChannels>>) -> Self {
        Self {
            config: config.clone(),
            signatures: SignatureData::load_embedded(),
            ebpf_channels,
            llm_ips: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

}

/// A single TCP connection entry parsed from `/proc/net/tcp`.
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub state: u8,
}

/// Parse a hex-encoded IP:PORT pair from `/proc/net/tcp`.
///
/// The format is `AABBCCDD:XXXX` where the IP is little-endian on
/// little-endian systems.
pub fn parse_hex_addr(addr: &str) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = addr.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip_hex = u32::from_str_radix(parts[0], 16).ok()?;
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    // /proc/net/tcp stores IPs in little-endian byte order; swap to get the
    // correct network (big-endian) representation before constructing the address.
    let ip = IpAddr::V4(std::net::Ipv4Addr::from(ip_hex.to_be()));

    Some((ip, port))
}

/// Parse a single data line from `/proc/net/tcp`.
///
/// Format (space-separated fields):
/// `sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode`
pub fn parse_proc_tcp_line(line: &str) -> Option<TcpConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let local = parse_hex_addr(parts[1])?;
    let remote = parse_hex_addr(parts[2])?;
    let state: u8 = u8::from_str_radix(parts[3], 16).ok()?;

    Some(TcpConnection {
        local_ip: local.0,
        local_port: local.1,
        remote_ip: remote.0,
        remote_port: remote.1,
        state,
    })
}

/// Read and parse `/proc/net/tcp`, returning only ESTABLISHED connections.
pub fn read_proc_tcp() -> Vec<TcpConnection> {
    let contents = match std::fs::read_to_string("/proc/net/tcp") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    contents
        .lines()
        .skip(1) // skip the header line
        .filter_map(parse_proc_tcp_line)
        .filter(|c| c.state == TCP_ESTABLISHED)
        .collect()
}

#[async_trait]
impl Detector for TrafficAnalyzerDetector {
    fn name(&self) -> &str {
        "traffic_analyzer"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::TrafficAnalyzer
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        // Resolve LLM API domains off the async runtime — getaddrinfo blocks.
        let domains: Vec<String> = self
            .signatures
            .llm_domains
            .iter()
            .take(25)
            .cloned()
            .collect();
        let ips = tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            let mut out = std::collections::HashSet::new();
            for domain in &domains {
                let host = domain.split(':').next().unwrap_or(domain);
                let target = format!("{}:443", host);
                if let Ok(addrs) = target.to_socket_addrs() {
                    for addr in addrs {
                        out.insert(addr.ip());
                    }
                }
            }
            out
        })
        .await
        .unwrap_or_default();
        if let Ok(mut guard) = self.llm_ips.lock() {
            *guard = ips;
        }
        Ok(())
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        // Try eBPF passive mode first
        if let Some(ref channels) = self.ebpf_channels {
            let mut conn_rx = channels.conn_tx.subscribe();
            let mut traffic_rx = channels.traffic_tx.subscribe();
            let duration = std::time::Duration::from_secs(5);
            let deadline = tokio::time::Instant::now() + duration;
            let target_set: std::collections::HashSet<IpAddr> =
                targets.iter().copied().collect();

            // Per-host tracking: remote ports and connection count
            let mut host_ports: HashMap<IpAddr, std::collections::HashSet<u16>> = HashMap::new();
            let mut host_conn_count: HashMap<IpAddr, usize> = HashMap::new();

            // Collect connection events
            loop {
                match tokio::time::timeout_at(deadline, conn_rx.recv()).await {
                    Ok(Ok(event)) => {
                        let dst_ip = std::net::Ipv4Addr::from(event.dst_addr);
                        // Check if the source (local) machine is in our target set
                        // Connection events track outbound connections
                        let src_ip = std::net::Ipv4Addr::from(event.src_addr);
                        let local = if target_set.contains(&IpAddr::V4(src_ip)) {
                            IpAddr::V4(src_ip)
                        } else if event.src_addr == 0 {
                            // src_addr=0 means we couldn't determine it; check if dst is LLM port
                            if LLM_API_PORTS.contains(&event.dst_port) {
                                // Attribute to first target as a heuristic
                                if let Some(&t) = targets.first() {
                                    t
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        };

                        host_ports
                            .entry(local)
                            .or_default()
                            .insert(event.dst_port);
                        *host_conn_count.entry(local).or_default() += 1;

                        // Also check LLM port connections
                        if LLM_API_PORTS.contains(&event.dst_port) {
                            host_ports.entry(local).or_default().insert(event.dst_port);
                        }
                        let _ = dst_ip; // used implicitly
                    }
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }

            // Also collect traffic timing events briefly
            let deadline2 = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                match tokio::time::timeout_at(deadline2, traffic_rx.recv()).await {
                    Ok(Ok(event)) => {
                        let src_ip = std::net::Ipv4Addr::from(event.src_addr);
                        if target_set.contains(&IpAddr::V4(src_ip)) {
                            host_ports
                                .entry(IpAddr::V4(src_ip))
                                .or_default()
                                .insert(event.dst_port);
                            *host_conn_count.entry(IpAddr::V4(src_ip)).or_default() += 1;
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }

            let mut signals = Vec::new();
            for (ip, ports) in &host_ports {
                let conn_count = host_conn_count.get(ip).copied().unwrap_or(0);

                // Check for LLM port connections
                let llm_ports: Vec<u16> = ports
                    .iter()
                    .filter(|p| LLM_API_PORTS.contains(p))
                    .copied()
                    .collect();
                if !llm_ports.is_empty() {
                    signals.push(Signal::new(
                        DetectorType::TrafficAnalyzer,
                        "active_llm_connections".to_string(),
                        format!("Host {} has connections to LLM API ports (eBPF)", ip),
                        Confidence::High,
                        serde_json::json!({
                            "ip": ip.to_string(),
                            "ports": llm_ports,
                            "source": "ebpf",
                        }),
                    ));
                }

                // Behavioral heuristic
                if ports.len() >= 3 && conn_count >= 5 {
                    signals.push(Signal::new(
                        DetectorType::TrafficAnalyzer,
                        "agent_behavior_pattern".to_string(),
                        format!(
                            "Host {} shows diverse connection pattern ({} unique ports, {} connections, eBPF)",
                            ip, ports.len(), conn_count
                        ),
                        Confidence::Medium,
                        serde_json::json!({
                            "ip": ip.to_string(),
                            "unique_ports": ports.len(),
                            "total_connections": conn_count,
                            "source": "ebpf",
                        }),
                    ));
                }
            }

            if !signals.is_empty() {
                return Ok(signals);
            }
            // Fall through to active mode if no eBPF events captured
        }

        // Active mode: read the local kernel's TCP table and report when the
        // *local* host is talking to a known LLM API IP on port 443. This
        // mirrors the Python implementation. Without a host agent or eBPF on
        // the target, we cannot observe a remote host's egress, so we never
        // attribute proc/net/tcp connections back to the target IP.
        let connections = tokio::task::spawn_blocking(read_proc_tcp).await?;
        let llm_ips: std::collections::HashSet<IpAddr> = self
            .llm_ips
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        if llm_ips.is_empty() {
            return Ok(Vec::new());
        }

        // Group LLM-bound connections by local_ip.
        let mut by_local: HashMap<IpAddr, Vec<&TcpConnection>> = HashMap::new();
        for c in &connections {
            if c.remote_port == 443 && llm_ips.contains(&c.remote_ip) {
                by_local.entry(c.local_ip).or_default().push(c);
            }
        }

        let mut signals = Vec::new();
        for (local_ip, conns) in by_local {
            let unique_remotes: std::collections::HashSet<IpAddr> =
                conns.iter().map(|c| c.remote_ip).collect();
            let preview: Vec<serde_json::Value> = conns
                .iter()
                .take(10)
                .map(|c| {
                    serde_json::json!({
                        "local_ip": c.local_ip.to_string(),
                        "local_port": c.local_port,
                        "remote_ip": c.remote_ip.to_string(),
                        "remote_port": c.remote_port,
                    })
                })
                .collect();
            signals.push(Signal::new(
                DetectorType::TrafficAnalyzer,
                "active_llm_connections".to_string(),
                format!(
                    "Host {} has {} active connection(s) to {} LLM API endpoint(s)",
                    local_ip,
                    conns.len(),
                    unique_remotes.len(),
                ),
                Confidence::High,
                serde_json::json!({
                    "ip": local_ip.to_string(),
                    "connection_count": conns.len(),
                    "unique_llm_endpoints": unique_remotes.len(),
                    "connections": preview,
                    "method": "proc_net_tcp",
                }),
            ));
        }

        Ok(signals)
    }
}
