use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};

use super::Detector;

/// Ports to probe for HTTP-based agent endpoints.
pub const PROBE_PORTS: &[u16] = &[
    80, 443, 3000, 3001, 3080, 3100, 5000, 8000, 8001, 8080, 8501, 11434,
];

/// Well-known metadata paths that indicate AI agent presence.
const METADATA_PATHS: &[&str] = &[
    "/.well-known/agents.json",
    "/.well-known/ai-plugin.json",
    "/.well-known/agent-identity.json",
    "/AGENTS.md",
    "/SKILL.md",
    "/MEMORY.md",
];

/// OpenAPI / documentation paths.
const OPENAPI_PATHS: &[&str] = &["/openapi.json", "/docs", "/swagger.json", "/api-docs"];

/// A single framework signature with endpoint paths and header prefixes.
struct FrameworkSignature {
    name: &'static str,
    endpoints: &'static [&'static str],
    header_prefixes: &'static [&'static str],
}

/// Hardcoded framework signatures (will be loaded from signature files in Phase 6).
const FRAMEWORK_SIGNATURES: &[FrameworkSignature] = &[
    FrameworkSignature {
        name: "langchain",
        endpoints: &["/invoke", "/batch", "/stream"],
        header_prefixes: &["x-langchain-"],
    },
    FrameworkSignature {
        name: "crewai",
        endpoints: &["/api/v1/crews", "/api/v1/tasks"],
        header_prefixes: &[],
    },
    FrameworkSignature {
        name: "autogen",
        endpoints: &["/api/agents", "/api/v1/chat"],
        header_prefixes: &[],
    },
    FrameworkSignature {
        name: "ollama",
        endpoints: &["/api/generate", "/api/chat", "/api/tags"],
        header_prefixes: &[],
    },
    FrameworkSignature {
        name: "dify",
        endpoints: &["/v1/chat-messages", "/v1/workflows"],
        header_prefixes: &[],
    },
];

/// Endpoint prober detector that fingerprints AI agent frameworks via HTTP probing.
pub struct EndpointProberDetector {
    timeout: Duration,
    concurrency: usize,
    client: reqwest::Client,
}

impl EndpointProberDetector {
    /// Create a new endpoint prober from scan configuration.
    pub fn new(config: &ScanConfig) -> Self {
        let timeout = Duration::from_secs_f64(config.http_timeout);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build reqwest client");

        Self {
            timeout,
            concurrency: config.http_concurrency,
            client,
        }
    }

    /// Quick TCP connect check to see if a port is open.
    async fn is_port_open(ip: IpAddr, port: u16) -> bool {
        let addr = std::net::SocketAddr::new(ip, port);
        tokio::time::timeout(Duration::from_millis(500), TcpStream::connect(addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }

    /// Build the base URL for a given host and port.
    fn base_url(ip: IpAddr, port: u16) -> String {
        let scheme = if port == 443 { "https" } else { "http" };
        if ip.is_ipv6() {
            format!("{}://[{}]:{}", scheme, ip, port)
        } else {
            format!("{}://{}:{}", scheme, ip, port)
        }
    }

    /// Probe a single URL path and return the response status and body snippet.
    async fn probe_path(
        &self,
        base: &str,
        path: &str,
    ) -> Option<(u16, reqwest::header::HeaderMap, String)> {
        let url = format!("{}{}", base, path);
        let resp = self.client.get(&url).send().await.ok()?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        // Read up to 8 KB of body for pattern matching.
        let body = resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(8192)
            .collect::<String>();
        Some((status, headers, body))
    }

    /// Probe framework endpoints on a single host:port.
    async fn probe_host_port(&self, ip: IpAddr, port: u16) -> Vec<Signal> {
        let base = Self::base_url(ip, port);
        let mut signals = Vec::new();

        // --- Framework endpoint probing ---
        for sig in FRAMEWORK_SIGNATURES {
            for &endpoint in sig.endpoints {
                if let Some((status, headers, _body)) = self.probe_path(&base, endpoint).await {
                    if !(400..=499).contains(&status) && status != 502 && status != 503 {
                        // Check for matching header prefixes
                        let header_match = if sig.header_prefixes.is_empty() {
                            false
                        } else {
                            headers.keys().any(|k| {
                                let k_str = k.as_str().to_lowercase();
                                sig.header_prefixes
                                    .iter()
                                    .any(|prefix| k_str.starts_with(prefix))
                            })
                        };

                        let confidence = if header_match {
                            Confidence::High
                        } else {
                            Confidence::Medium
                        };

                        let description = format!(
                            "{} framework endpoint {} responded on {}:{}",
                            sig.name, endpoint, ip, port
                        );

                        let evidence = serde_json::json!({
                            "ip": ip.to_string(),
                            "port": port,
                            "framework": sig.name,
                            "endpoint": endpoint,
                            "status": status,
                            "header_match": header_match,
                        });

                        signals.push(Signal::new(
                            DetectorType::EndpointProber,
                            "framework_endpoint_match".to_string(),
                            description,
                            confidence,
                            evidence,
                        ));

                        // One match per framework is enough
                        break;
                    }
                }
            }
        }

        // --- Metadata path probing ---
        for &path in METADATA_PATHS {
            if let Some((status, _headers, body)) = self.probe_path(&base, path).await {
                if (200..=299).contains(&status) && !body.is_empty() {
                    let description = format!(
                        "Agent metadata found at {}{} on {}:{}",
                        base, path, ip, port
                    );

                    let evidence = serde_json::json!({
                        "ip": ip.to_string(),
                        "port": port,
                        "path": path,
                        "status": status,
                        "body_preview": &body[..body.len().min(512)],
                    });

                    signals.push(Signal::new(
                        DetectorType::EndpointProber,
                        "agent_metadata_found".to_string(),
                        description,
                        Confidence::High,
                        evidence,
                    ));
                }
            }
        }

        // --- OpenAPI path probing ---
        for &path in OPENAPI_PATHS {
            if let Some((status, _headers, body)) = self.probe_path(&base, path).await {
                if (200..=299).contains(&status) && !body.is_empty() {
                    let description = format!(
                        "OpenAPI/docs spec found at {}{} on {}:{}",
                        base, path, ip, port
                    );

                    let evidence = serde_json::json!({
                        "ip": ip.to_string(),
                        "port": port,
                        "path": path,
                        "status": status,
                        "body_preview": &body[..body.len().min(512)],
                    });

                    signals.push(Signal::new(
                        DetectorType::EndpointProber,
                        "agent_openapi_spec".to_string(),
                        description,
                        Confidence::Medium,
                        evidence,
                    ));
                }
            }
        }

        signals
    }
}

#[async_trait]
impl Detector for EndpointProberDetector {
    fn name(&self) -> &str {
        "endpoint_prober"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::EndpointProber
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        let semaphore = std::sync::Arc::new(Semaphore::new(self.concurrency));
        let mut handles = Vec::new();

        for &ip in targets {
            // Pre-filter: check which ports are open
            let mut open_ports = Vec::new();
            for &port in PROBE_PORTS {
                if Self::is_port_open(ip, port).await {
                    open_ports.push(port);
                }
            }

            if open_ports.is_empty() {
                continue;
            }

            for port in open_ports {
                let permit = semaphore.clone().acquire_owned().await?;
                let client = self.client.clone();
                let timeout = self.timeout;
                let concurrency = self.concurrency;

                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let detector = EndpointProberDetector {
                        timeout,
                        concurrency,
                        client,
                    };
                    detector.probe_host_port(ip, port).await
                });

                handles.push(handle);
            }
        }

        let mut signals = Vec::new();
        for handle in handles {
            if let Ok(sigs) = handle.await {
                signals.extend(sigs);
            }
        }

        Ok(signals)
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
