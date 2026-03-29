//! Nmap enricher: runs nmap as a subprocess, parses XML output, and adds/adjusts signals.

use std::collections::HashSet;

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::models::{Confidence, DetectedAgent, DetectorType, Signal};
use super::Enricher;

/// Classification of a service by its agent-relevance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceClass {
    AgentLike,
    NonAgent,
    Unknown,
}

/// Services that suggest an AI agent or AI-adjacent framework.
const AGENT_LIKE_SERVICES: &[&str] = &[
    "uvicorn", "gunicorn", "hypercorn",
    "node", "nodejs", "express",
    "ollama", "lm-studio", "vllm",
    "streamlit", "gradio", "fastapi",
];

/// Services that are clearly non-agent infrastructure.
const NON_AGENT_SERVICES: &[&str] = &[
    "cups", "ipp", "printer",
    "postgresql", "mysql", "mariadb", "redis", "mongodb", "memcached",
    "sshd", "ssh",
    "postfix", "dovecot", "smtp", "imap", "pop3",
    "squid", "haproxy",
    "apache httpd", "nginx",
    "samba", "smb", "nfs",
    "dhcpd", "ntpd", "snmp",
    "ldap", "kerberos",
];

/// Detectors whose signals corroborate agent presence, preventing confidence reduction.
const CORROBORATING_DETECTORS: &[DetectorType] = &[
    DetectorType::EndpointProber,
    DetectorType::McpDetector,
    DetectorType::AgentpinProber,
    DetectorType::DnsMonitor,
    DetectorType::TrafficAnalyzer,
    DetectorType::TlsFingerprint,
    DetectorType::SseDetector,
];

/// Classify a service name string as agent-like, non-agent, or unknown.
///
/// Comparison is case-insensitive and checks both `AGENT_LIKE_SERVICES` and
/// `NON_AGENT_SERVICES` lists.
pub fn classify_service(name: &str) -> ServiceClass {
    let lower = name.to_lowercase();
    if AGENT_LIKE_SERVICES.contains(&lower.as_str()) {
        return ServiceClass::AgentLike;
    }
    if NON_AGENT_SERVICES.contains(&lower.as_str()) {
        return ServiceClass::NonAgent;
    }
    ServiceClass::Unknown
}

/// A single open service discovered by nmap.
#[derive(Debug, Clone)]
pub struct NmapService {
    pub port: u16,
    pub protocol: String,
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub state: String,
}

/// A host with its open services as discovered by nmap.
#[derive(Debug, Clone)]
pub struct NmapHost {
    pub ip: String,
    pub services: Vec<NmapService>,
}

/// Parse nmap XML output (from `nmap -oX -`) into a list of hosts.
pub fn parse_nmap_xml(xml: &str) -> Vec<NmapHost> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut hosts: Vec<NmapHost> = Vec::new();

    let mut in_host = false;
    let mut current_ip: Option<String> = None;
    let mut current_services: Vec<NmapService> = Vec::new();

    // Per-port state
    let mut current_port: Option<u16> = None;
    let mut current_protocol: Option<String> = None;
    let mut current_state: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = e.name();
                let tag = std::str::from_utf8(name.as_ref()).unwrap_or("");

                match tag {
                    "host" => {
                        in_host = true;
                        current_ip = None;
                        current_services = Vec::new();
                        current_port = None;
                        current_protocol = None;
                        current_state = None;
                    }
                    "address" if in_host => {
                        let mut addr_val: Option<String> = None;
                        let mut addr_type: Option<String> = None;
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            let val = attr.unescape_value().unwrap_or_default().into_owned();
                            match key {
                                "addr" => addr_val = Some(val),
                                "addrtype" => addr_type = Some(val),
                                _ => {}
                            }
                        }
                        if addr_type.as_deref() == Some("ipv4") {
                            current_ip = addr_val;
                        }
                    }
                    "port" if in_host => {
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            let val = attr.unescape_value().unwrap_or_default().into_owned();
                            match key {
                                "portid" => {
                                    current_port = val.parse().ok();
                                }
                                "protocol" => {
                                    current_protocol = Some(val);
                                }
                                _ => {}
                            }
                        }
                        current_state = None;
                    }
                    "state" if in_host => {
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            let val = attr.unescape_value().unwrap_or_default().into_owned();
                            if key == "state" {
                                current_state = Some(val);
                            }
                        }
                    }
                    "service" if in_host => {
                        if let Some(port) = current_port {
                            let mut svc_name: Option<String> = None;
                            let mut product: Option<String> = None;
                            let mut version: Option<String> = None;
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                let val = attr.unescape_value().unwrap_or_default().into_owned();
                                match key {
                                    "name" => svc_name = Some(val),
                                    "product" => product = Some(val),
                                    "version" => version = Some(val),
                                    _ => {}
                                }
                            }
                            let svc = NmapService {
                                port,
                                protocol: current_protocol.clone().unwrap_or_else(|| "tcp".to_string()),
                                name: svc_name,
                                product,
                                version,
                                state: current_state.clone().unwrap_or_else(|| "open".to_string()),
                            };
                            current_services.push(svc);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name_end = e.name();
                let tag = std::str::from_utf8(name_end.as_ref()).unwrap_or("");
                match tag {
                    "host" if in_host => {
                        if let Some(ip) = current_ip.take() {
                            hosts.push(NmapHost {
                                ip,
                                services: std::mem::take(&mut current_services),
                            });
                        }
                        in_host = false;
                        current_port = None;
                        current_protocol = None;
                        current_state = None;
                    }
                    "port" => {
                        current_port = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    hosts
}

/// Enricher that runs nmap against detected agents and adjusts confidence based on findings.
pub struct NmapEnricher {
    scan_args: String,
    timeout_secs: u64,
}

impl NmapEnricher {
    /// Create a new enricher.
    ///
    /// `scan_args` is passed verbatim before `-oX - <ip>`, e.g. `"-sV -T4"`.
    pub fn new(scan_args: &str, timeout_secs: u64) -> Self {
        Self {
            scan_args: scan_args.to_string(),
            timeout_secs,
        }
    }

    /// Run nmap against a single IP and return raw XML output.
    pub async fn run_nmap(&self, ip: &str) -> anyhow::Result<String> {
        use tokio::process::Command;
        use tokio::time::{timeout, Duration};

        let mut cmd = Command::new("nmap");
        // Split scan_args on whitespace and add each as a separate argument
        for arg in self.scan_args.split_whitespace() {
            cmd.arg(arg);
        }
        cmd.arg("-oX").arg("-").arg(ip);

        let fut = async move {
            let output = cmd.output().await?;
            if !output.status.success() {
                anyhow::bail!(
                    "nmap exited with status {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let xml = String::from_utf8_lossy(&output.stdout).into_owned();
            Ok::<String, anyhow::Error>(xml)
        };

        timeout(Duration::from_secs(self.timeout_secs), fut)
            .await
            .map_err(|_| anyhow::anyhow!("nmap timed out for {ip}"))?
    }
}

#[async_trait]
impl Enricher for NmapEnricher {
    async fn enrich(&self, mut agents: Vec<DetectedAgent>) -> anyhow::Result<Vec<DetectedAgent>> {
        // Check if nmap is available
        match tokio::process::Command::new("nmap").arg("--version").output().await {
            Ok(output) if output.status.success() => {}
            _ => {
                tracing::warn!("nmap binary not found or not working; skipping enrichment");
                return Ok(agents);
            }
        }

        let corroborating: HashSet<DetectorType> =
            CORROBORATING_DETECTORS.iter().copied().collect();

        for agent in &mut agents {
            let ip = agent.ip_address.to_string();

            let xml = match self.run_nmap(&ip).await {
                Ok(x) => x,
                Err(_) => continue,
            };

            let hosts = parse_nmap_xml(&xml);
            let host = match hosts.iter().find(|h| h.ip == ip) {
                Some(h) => h,
                None => continue,
            };

            // Serialize services into agent metadata
            let services_json: Vec<serde_json::Value> = host
                .services
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "port": s.port,
                        "protocol": s.protocol,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                        "state": s.state,
                    })
                })
                .collect();

            if let Some(obj) = agent.metadata.as_object_mut() {
                obj.insert("nmap_services".to_string(), serde_json::json!(services_json));
            }

            // Add agent-like signals; track whether any non-agent services exist
            let mut has_agent_like = false;
            let mut all_non_agent = true;

            for svc in &host.services {
                // Check product first, then service name
                let product_class = svc
                    .product
                    .as_deref()
                    .map(classify_service)
                    .unwrap_or(ServiceClass::Unknown);
                let name_class = svc
                    .name
                    .as_deref()
                    .map(classify_service)
                    .unwrap_or(ServiceClass::Unknown);

                let best_class = if product_class == ServiceClass::AgentLike
                    || name_class == ServiceClass::AgentLike
                {
                    ServiceClass::AgentLike
                } else if product_class == ServiceClass::NonAgent
                    || name_class == ServiceClass::NonAgent
                {
                    ServiceClass::NonAgent
                } else {
                    ServiceClass::Unknown
                };

                match best_class {
                    ServiceClass::AgentLike => {
                        has_agent_like = true;
                        all_non_agent = false;
                        let label = svc
                            .product
                            .as_deref()
                            .or(svc.name.as_deref())
                            .unwrap_or("unknown");
                        let sig = Signal::new(
                            DetectorType::NmapEnricher,
                            "nmap_service_match".to_string(),
                            format!("Agent-like service detected on port {}: {label}", svc.port),
                            Confidence::Medium,
                            serde_json::json!({
                                "port": svc.port,
                                "product": svc.product,
                                "name": svc.name,
                            }),
                        );
                        agent.signals.push(sig);
                    }
                    ServiceClass::Unknown => {
                        all_non_agent = false;
                    }
                    ServiceClass::NonAgent => {}
                }
            }

            // Suppress confidence if all services are non-agent and no corroborating signals
            let has_corroborating = agent
                .signals
                .iter()
                .any(|s| corroborating.contains(&s.detector));

            if all_non_agent && !has_agent_like && !has_corroborating {
                agent.confidence_score *= 0.5;
            }

            // Always sync status from signals (adds agent-like signals above)
            agent.update_status();
        }

        Ok(agents)
    }
}
