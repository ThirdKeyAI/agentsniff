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
pub struct TrafficAnalyzerDetector {
    #[allow(dead_code)]
    config: ScanConfig,
    #[allow(dead_code)]
    signatures: SignatureData,
    ebpf_channels: Option<Arc<EbpfChannels>>,
}

impl TrafficAnalyzerDetector {
    pub fn new(config: &ScanConfig, ebpf_channels: Option<Arc<EbpfChannels>>) -> Self {
        Self {
            config: config.clone(),
            signatures: SignatureData::load_embedded(),
            ebpf_channels,
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

        // Read the current TCP connection table from the kernel.
        let connections = tokio::task::spawn_blocking(read_proc_tcp).await?;

        let mut signals = Vec::new();

        for &target in targets {
            // Collect connections where the target is either the local or remote end.
            let target_conns: Vec<&TcpConnection> = connections
                .iter()
                .filter(|c| c.local_ip == target || c.remote_ip == target)
                .collect();

            if target_conns.is_empty() {
                continue;
            }

            // Check for connections to known LLM API ports on the remote end.
            let llm_connections: Vec<&&TcpConnection> = target_conns
                .iter()
                .filter(|c| LLM_API_PORTS.contains(&c.remote_port))
                .collect();

            if !llm_connections.is_empty() {
                let ports: Vec<u16> = llm_connections.iter().map(|c| c.remote_port).collect();
                signals.push(Signal::new(
                    DetectorType::TrafficAnalyzer,
                    "active_llm_connections".to_string(),
                    format!(
                        "Host {} has {} active connection(s) to LLM API ports",
                        target,
                        llm_connections.len()
                    ),
                    Confidence::High,
                    serde_json::json!({
                        "ip": target.to_string(),
                        "connection_count": llm_connections.len(),
                        "ports": ports,
                    }),
                ));
            }

            // Behavioral heuristic: many diverse remote ports suggest ORA-loop activity.
            let unique_remote_ports: std::collections::HashSet<u16> =
                target_conns.iter().map(|c| c.remote_port).collect();

            if unique_remote_ports.len() >= 3 && target_conns.len() >= 5 {
                signals.push(Signal::new(
                    DetectorType::TrafficAnalyzer,
                    "agent_behavior_pattern".to_string(),
                    format!(
                        "Host {} shows diverse connection pattern ({} unique ports, {} connections)",
                        target,
                        unique_remote_ports.len(),
                        target_conns.len()
                    ),
                    Confidence::Medium,
                    serde_json::json!({
                        "ip": target.to_string(),
                        "unique_ports": unique_remote_ports.len(),
                        "total_connections": target_conns.len(),
                    }),
                ));
            }
        }

        Ok(signals)
    }
}
