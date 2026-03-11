use std::net::IpAddr;

use async_trait::async_trait;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

/// Ports commonly used by LLM APIs.
const LLM_API_PORTS: &[u16] = &[443, 8080, 11434, 3000];

/// TCP state for ESTABLISHED connections in /proc/net/tcp.
const TCP_ESTABLISHED: u8 = 1;

/// Traffic analyzer detector.
///
/// Operates in fallback mode by reading `/proc/net/tcp` to detect active
/// connections to known LLM API ports and behavioral patterns consistent
/// with Observe-Reason-Act (ORA) agent loops.
pub struct TrafficAnalyzerDetector {
    #[allow(dead_code)]
    config: ScanConfig,
    #[allow(dead_code)]
    signatures: SignatureData,
}

impl TrafficAnalyzerDetector {
    /// Create a new traffic analyzer detector from scan configuration.
    pub fn new(config: &ScanConfig) -> Self {
        Self {
            config: config.clone(),
            signatures: SignatureData::load_embedded(),
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
