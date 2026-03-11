use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};

use super::Detector;

/// Known AI agent ports: (port, name, description).
const AGENT_PORTS: &[(u16, &str, &str)] = &[
    (11434, "ollama", "Ollama LLM server"),
    (1234, "lm_studio", "LM Studio API"),
    (6333, "qdrant_http", "Qdrant vector DB HTTP"),
    (6334, "qdrant_grpc", "Qdrant vector DB gRPC"),
    (8090, "weaviate", "Weaviate vector DB"),
    (19530, "milvus", "Milvus vector DB"),
    (3080, "librechat", "LibreChat"),
    (3100, "dify", "Dify AI platform"),
    (8501, "streamlit", "Streamlit app"),
    (4000, "litellm", "LiteLLM proxy"),
    (2024, "langgraph_studio", "LangGraph Studio"),
    (8283, "letta", "Letta agent framework"),
    (65432, "continue_dev", "Continue.dev IDE plugin"),
    (7860, "text_gen_webui", "Text Generation WebUI"),
    (5001, "koboldcpp", "KoboldCpp"),
    (1337, "jan", "Jan AI"),
    (8443, "code_server", "Code Server"),
];

/// Generic HTTP ports that may host agent services (LOW confidence).
const GENERIC_PORTS: &[u16] = &[3000, 3001, 5000, 8000, 8001, 8080];

/// Banner patterns: (pattern, service_name).
const BANNER_PATTERNS: &[(&str, &str)] = &[
    ("ollama", "ollama"),
    ("qdrant", "qdrant"),
    ("weaviate", "weaviate"),
    ("milvus", "milvus"),
    ("redis", "redis"),
    ("lm studio", "lm_studio"),
];

/// Classify a port number into a known agent service or generic HTTP.
///
/// Returns `Some((service_name, confidence))` or `None` for unknown ports.
pub fn classify_port(port: u16) -> Option<(&'static str, Confidence)> {
    for &(p, name, _) in AGENT_PORTS {
        if p == port {
            return Some((name, Confidence::Medium));
        }
    }
    if GENERIC_PORTS.contains(&port) {
        return Some(("generic_http", Confidence::Low));
    }
    None
}

/// Classify a banner string against known patterns.
///
/// Performs case-insensitive matching and returns the service name if matched.
pub fn classify_banner(banner: &str) -> Option<&'static str> {
    let lower = banner.to_lowercase();
    for &(pattern, name) in BANNER_PATTERNS {
        if lower.contains(pattern) {
            return Some(name);
        }
    }
    None
}

/// Port scanner detector that probes known AI agent ports on target hosts.
pub struct PortScannerDetector {
    ports: Vec<u16>,
    timeout: Duration,
    concurrency: usize,
}

impl PortScannerDetector {
    /// Create a new port scanner from scan configuration.
    pub fn new(config: &ScanConfig) -> Self {
        let mut ports: Vec<u16> = Vec::new();

        // Add known agent ports
        for &(port, _, _) in AGENT_PORTS {
            ports.push(port);
        }

        // Add generic ports
        for &port in GENERIC_PORTS {
            ports.push(port);
        }

        // Add custom ports
        for &port in config.custom_agent_ports.keys() {
            ports.push(port);
        }

        // Deduplicate and sort
        ports.sort_unstable();
        ports.dedup();

        let timeout = Duration::from_secs_f64(config.port_scan_timeout);
        let concurrency = config.port_scan_concurrency;

        Self {
            ports,
            timeout,
            concurrency,
        }
    }

    /// Returns the number of ports that will be scanned.
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
        let semaphore = std::sync::Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for &ip in targets {
            for &port in &self.ports {
                let permit = semaphore.clone().acquire_owned().await?;
                let timeout = self.timeout;
                let banner_timeout = Duration::from_millis(500);

                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let addr = std::net::SocketAddr::new(ip, port);

                    // TCP connect with timeout
                    let mut stream =
                        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                            Ok(Ok(s)) => s,
                            _ => return None,
                        };

                    let mut buf = vec![0u8; 4096];

                    // Try reading a banner
                    let banner =
                        match tokio::time::timeout(banner_timeout, stream.read(&mut buf)).await {
                            Ok(Ok(n)) if n > 0 => {
                                Some(String::from_utf8_lossy(&buf[..n]).to_string())
                            }
                            _ => None,
                        };

                    // If no banner, try HTTP GET probe
                    let banner = if banner.is_none() {
                        let http_req = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
                        let _ = stream.write_all(http_req.as_bytes()).await;
                        match tokio::time::timeout(banner_timeout, stream.read(&mut buf)).await {
                            Ok(Ok(n)) if n > 0 => {
                                Some(String::from_utf8_lossy(&buf[..n]).to_string())
                            }
                            _ => None,
                        }
                    } else {
                        banner
                    };

                    // Classify
                    let (service, confidence, signal_type) = if let Some(ref b) = banner {
                        if let Some(svc) = classify_banner(b) {
                            (
                                svc.to_string(),
                                Confidence::Medium,
                                "agent_service_identified".to_string(),
                            )
                        } else if let Some((svc, conf)) = classify_port(port) {
                            (
                                svc.to_string(),
                                conf,
                                if conf >= Confidence::Medium {
                                    "agent_service_identified".to_string()
                                } else {
                                    "open_agent_port".to_string()
                                },
                            )
                        } else {
                            return None;
                        }
                    } else if let Some((svc, conf)) = classify_port(port) {
                        (
                            svc.to_string(),
                            conf,
                            if conf >= Confidence::Medium {
                                "agent_service_identified".to_string()
                            } else {
                                "open_agent_port".to_string()
                            },
                        )
                    } else {
                        return None;
                    };

                    let description =
                        format!("Port {} open on {} - {} service", port, ip, service);

                    let evidence = serde_json::json!({
                        "ip": ip.to_string(),
                        "port": port,
                        "service": service,
                        "banner": banner.as_deref().unwrap_or(""),
                    });

                    Some(Signal::new(
                        DetectorType::PortScanner,
                        signal_type,
                        description,
                        confidence,
                        evidence,
                    ))
                });

                handles.push(handle);
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
