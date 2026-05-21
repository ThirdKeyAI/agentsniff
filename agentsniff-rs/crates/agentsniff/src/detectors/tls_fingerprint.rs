use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::config::ScanConfig;
use crate::ebpf::EbpfChannels;
use crate::models::{Confidence, DetectorType, Signal};

use super::Detector;

/// Known TLS ports to probe for fingerprinting.
const TLS_PROBE_PORTS: &[u16] = &[443, 8443, 3000, 5000, 8000, 8080, 11434];

/// TLS fingerprint detector.
///
/// When eBPF channels are available, operates in passive mode by subscribing
/// to TLS ClientHello events from the kernel. Falls back to active HTTPS
/// probing when eBPF is unavailable.
pub struct TlsFingerprintDetector {
    #[allow(dead_code)]
    config: ScanConfig,
    timeout: Duration,
    client: reqwest::Client,
    ebpf_channels: Option<Arc<EbpfChannels>>,
}

impl TlsFingerprintDetector {
    pub fn new(config: &ScanConfig, ebpf_channels: Option<Arc<EbpfChannels>>) -> Self {
        let timeout = Duration::from_secs_f64(config.port_scan_timeout);
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(timeout)
            .build()
            .expect("failed to build reqwest client for TLS fingerprinting");

        Self {
            config: config.clone(),
            timeout,
            client,
            ebpf_channels,
        }
    }

    /// Quick TCP connect to check if a port is open before attempting TLS.
    async fn is_port_open(ip: IpAddr, port: u16, timeout: Duration) -> bool {
        let addr = std::net::SocketAddr::new(ip, port);
        tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }
}

/// Compute a simplified JA3-style fingerprint string from TLS handshake parameters.
///
/// JA3 format: `TLSVersion,Ciphers,Extensions` where values are decimal and
/// multiple values are dash-separated. This is a simplified variant that omits
/// elliptic curves and point formats (those require deeper packet inspection).
pub fn compute_ja3_string(tls_version: u16, cipher_suites: &[u16], extensions: &[u16]) -> String {
    let ciphers = cipher_suites
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let exts = extensions
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!("{},{},{}", tls_version, ciphers, exts)
}

/// Result of a TLS probe attempt.
struct TlsProbeResult {
    tls_version: Option<String>,
}

/// Attempt an HTTPS connection and extract the TLS version from the response.
async fn probe_tls(
    client: &reqwest::Client,
    ip: IpAddr,
    port: u16,
) -> anyhow::Result<TlsProbeResult> {
    let url = if ip.is_ipv6() {
        format!("https://[{}]:{}/", ip, port)
    } else {
        format!("https://{}:{}/", ip, port)
    };

    match client.get(&url).send().await {
        Ok(resp) => {
            let version = resp.version();
            Ok(TlsProbeResult {
                tls_version: Some(format!("{:?}", version)),
            })
        }
        Err(e) => {
            // If the error is a connection error, the port is not reachable.
            // Any other error (TLS cert issues, HTTP errors after connect) still
            // indicates a TLS endpoint was reached.
            if e.is_connect() {
                Err(anyhow::anyhow!("connection failed to {}:{}", ip, port))
            } else if e.is_timeout() {
                Err(anyhow::anyhow!("timeout connecting to {}:{}", ip, port))
            } else {
                // Got past TCP + TLS — treat as a live TLS endpoint.
                Ok(TlsProbeResult {
                    tls_version: Some("TLS (version unknown)".to_string()),
                })
            }
        }
    }
}

#[async_trait]
impl Detector for TlsFingerprintDetector {
    fn name(&self) -> &str {
        "tls_fingerprint"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::TlsFingerprint
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        // Try eBPF passive mode first
        if let Some(ref channels) = self.ebpf_channels {
            let mut rx = channels.tls_tx.subscribe();
            let duration = Duration::from_secs(5);
            let deadline = tokio::time::Instant::now() + duration;
            let mut signals = Vec::new();
            let target_set: std::collections::HashSet<IpAddr> =
                targets.iter().copied().collect();

            loop {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Ok(event)) => {
                        let src_ip = std::net::Ipv4Addr::from(event.src_addr);
                        if !target_set.contains(&IpAddr::V4(src_ip)) {
                            continue;
                        }
                        let ja3 = compute_ja3_string(
                            event.tls_version,
                            &event.cipher_suites[..event.cipher_count as usize],
                            &event.extensions[..event.extension_count as usize],
                        );
                        let dst_ip = std::net::Ipv4Addr::from(event.dst_addr);
                        signals.push(Signal::new(
                            DetectorType::TlsFingerprint,
                            "tls_fingerprint_captured".to_string(),
                            format!(
                                "TLS ClientHello from {} to {}:{} (JA3: {})",
                                src_ip, dst_ip, event.dst_port, ja3
                            ),
                            Confidence::Low,
                            serde_json::json!({
                                "ip": src_ip.to_string(),
                                "dst_ip": dst_ip.to_string(),
                                "dst_port": event.dst_port,
                                "ja3_string": ja3,
                                "tls_version": event.tls_version,
                                "source": "ebpf",
                            }),
                        ));
                    }
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }

            if !signals.is_empty() {
                return Ok(signals);
            }
        }

        let mut signals = Vec::new();

        for &ip in targets {
            for &port in TLS_PROBE_PORTS {
                // Quick TCP gate before attempting TLS handshake.
                if !Self::is_port_open(ip, port, self.timeout).await {
                    continue;
                }

                match probe_tls(&self.client, ip, port).await {
                    Ok(info) => {
                        if let Some(tls_version) = info.tls_version {
                            tracing::debug!(
                                "TLS endpoint detected at {}:{} ({})",
                                ip,
                                port,
                                tls_version
                            );

                            signals.push(Signal::new(
                                DetectorType::TlsFingerprint,
                                "tls_endpoint_detected".to_string(),
                                format!("TLS endpoint at {}:{} ({})", ip, port, tls_version),
                                Confidence::Low,
                                serde_json::json!({
                                    "ip": ip.to_string(),
                                    "port": port,
                                    "tls_version": tls_version,
                                }),
                            ));
                        }
                    }
                    Err(e) => {
                        tracing::trace!("TLS probe failed for {}:{}: {}", ip, port, e);
                    }
                }
            }
        }

        Ok(signals)
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

