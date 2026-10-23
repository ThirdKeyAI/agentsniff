use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

const BANNER_PATTERNS: &[(&str, &str)] = &[
    ("ollama", "ollama"),
    ("qdrant", "qdrant"),
    ("weaviate", "weaviate"),
    ("milvus", "milvus"),
    ("lm studio", "lmstudio"),
    ("sglang", "sglang"),
    ("litellm", "litellm"),
];

/// Look up a port in the signed catalog. Port-only evidence remains LOW
/// confidence because an unrelated application can bind any conventional
/// port; protocol or banner evidence is required for a stronger signal.
pub fn classify_port(port: u16) -> Option<(String, Confidence)> {
    let signatures = SignatureData::load_embedded();
    signatures
        .ports
        .get(&port)
        .map(|services| (services.join("|"), Confidence::Low))
}

pub fn classify_banner(banner: &str) -> Option<&'static str> {
    let lower = banner.to_ascii_lowercase();
    BANNER_PATTERNS
        .iter()
        .find_map(|(pattern, service)| lower.contains(pattern).then_some(*service))
}

pub struct PortScannerDetector {
    ports: Vec<u16>,
    services: Arc<HashMap<u16, Vec<String>>>,
    custom_ports: Arc<HashSet<u16>>,
    timeout: Duration,
    concurrency: usize,
}

impl PortScannerDetector {
    pub fn new(config: &ScanConfig) -> Self {
        let signatures = SignatureData::load_with_overlay();
        let mut services = signatures.ports;
        let custom_ports: HashSet<u16> = config.custom_agent_ports.keys().copied().collect();
        for (&port, service) in &config.custom_agent_ports {
            services.entry(port).or_default().push(service.clone());
        }
        for candidates in services.values_mut() {
            candidates.sort();
            candidates.dedup();
        }
        let mut ports: Vec<u16> = services.keys().copied().collect();
        ports.sort_unstable();
        // A probe port outside the catalog could never yield a signal, so skip it.
        let ports: Vec<u16> = config
            .ports_or(&ports)
            .into_iter()
            .filter(|port| services.contains_key(port))
            .collect();

        Self {
            ports,
            services: Arc::new(services),
            custom_ports: Arc::new(custom_ports),
            timeout: Duration::from_secs_f64(config.port_scan_timeout),
            concurrency: config.port_scan_concurrency.max(1),
        }
    }

    pub fn port_count(&self) -> usize {
        self.ports.len()
    }
}

#[async_trait]
impl Detector for PortScannerDetector {
    fn name(&self) -> &str {
        "port_scanner"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::PortScanner
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for &ip in targets {
            for &port in &self.ports {
                let permit = semaphore.clone().acquire_owned().await?;
                let timeout = self.timeout;
                let services = Arc::clone(&self.services);
                let custom_ports = Arc::clone(&self.custom_ports);
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    let addr = std::net::SocketAddr::new(ip, port);
                    crate::ratelimit::acquire().await;
                    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                        Ok(Ok(stream)) => stream,
                        _ => return None,
                    };

                    let banner_timeout = Duration::from_millis(500);
                    let mut buffer = vec![0u8; 4096];
                    let banner = match tokio::time::timeout(banner_timeout, stream.read(&mut buffer)).await {
                        Ok(Ok(count)) if count > 0 => {
                            Some(String::from_utf8_lossy(&buffer[..count]).to_string())
                        }
                        _ => None,
                    };
                    let banner = if banner.is_none() {
                        let request = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
                        let _ = stream.write_all(request.as_bytes()).await;
                        match tokio::time::timeout(banner_timeout, stream.read(&mut buffer)).await {
                            Ok(Ok(count)) if count > 0 => {
                                Some(String::from_utf8_lossy(&buffer[..count]).to_string())
                            }
                            _ => None,
                        }
                    } else {
                        banner
                    };

                    let candidates = services.get(&port)?.clone();
                    let banner_service = banner.as_deref().and_then(classify_banner);
                    let (service, confidence, signal_type) = if let Some(service) = banner_service {
                        (
                            service.to_string(),
                            Confidence::Medium,
                            "agent_service_identified",
                        )
                    } else if custom_ports.contains(&port) {
                        (
                            candidates.join("|"),
                            Confidence::Medium,
                            "custom_agent_port_open",
                        )
                    } else {
                        (candidates.join("|"), Confidence::Low, "open_agent_port")
                    };

                    Some(Signal::new(
                        DetectorType::PortScanner,
                        signal_type.to_string(),
                        format!("Port {} open on {} - candidate service(s): {}", port, ip, service),
                        confidence,
                        serde_json::json!({
                            "ip": ip.to_string(),
                            "port": port,
                            "service": service,
                            "service_candidates": candidates,
                            "banner": banner.as_deref().unwrap_or(""),
                            "signature_source": if custom_ports.contains(&port) { "custom" } else { "signed_catalog" },
                        }),
                    ))
                }));
            }
        }

        let mut signals = Vec::new();
        for handle in handles {
            if let Ok(Some(signal)) = handle.await {
                signals.push(signal);
            }
        }
        Ok(signals)
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
