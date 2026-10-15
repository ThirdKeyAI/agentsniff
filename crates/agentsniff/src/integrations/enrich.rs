//! Service enrichment for detected agents using permissively licensed tools
//! run as subprocesses: naabu (ports, MIT), httpx (web tech, MIT) and zgrab2
//! (banners, Apache-2.0). Also holds the service classification shared with
//! the Nmap XML importer.

use std::collections::{BTreeMap, HashSet};
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Enricher;
use crate::models::{Confidence, DetectedAgent, DetectorType, Signal};

/// Hard cap on a single tool's stdout, enforced while reading.
const MAX_TOOL_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Ports naabu checks per host, matching Nmap's default top-1000 coverage.
const NAABU_TOP_PORTS: &str = "1000";

/// zgrab2 modules for non-HTTP ports; mirrors the protocols in `NON_AGENT_SERVICES`.
const ZGRAB2_MODULES: &[&str] = &[
    "ssh",
    "smtp",
    "imap",
    "pop3",
    "ftp",
    "redis",
    "mysql",
    "postgres",
    "mongodb",
    "memcached",
];

/// Environment variables that could point ProjectDiscovery tools at their cloud.
const PDCP_ENV: &[&str] = &[
    "PDCP_API_KEY",
    "PDCP_API_SERVER",
    "PDCP_TEAM_ID",
    "ENABLE_CLOUD_UPLOAD",
];

/// Classification of a service by its agent-relevance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceClass {
    AgentLike,
    NonAgent,
    Unknown,
}

/// Services that suggest an AI agent or AI-adjacent framework.
const AGENT_LIKE_SERVICES: &[&str] = &[
    "uvicorn",
    "gunicorn",
    "hypercorn",
    "node",
    "nodejs",
    "express",
    "ollama",
    "lm-studio",
    "vllm",
    "streamlit",
    "gradio",
    "fastapi",
];

/// Services that are clearly non-agent infrastructure.
const NON_AGENT_SERVICES: &[&str] = &[
    "cups",
    "ipp",
    "printer",
    "postgresql",
    "postgres",
    "mysql",
    "mariadb",
    "redis",
    "mongodb",
    "memcached",
    "sshd",
    "ssh",
    "postfix",
    "dovecot",
    "smtp",
    "ftp",
    "imap",
    "pop3",
    "squid",
    "haproxy",
    "apache httpd",
    "nginx",
    "samba",
    "smb",
    "nfs",
    "dhcpd",
    "ntpd",
    "snmp",
    "ldap",
    "kerberos",
];

/// Detectors whose signals corroborate agent presence, preventing confidence reduction.
const CORROBORATING_DETECTORS: &[DetectorType] = &[
    DetectorType::EndpointProber,
    DetectorType::McpDetector,
    DetectorType::AgentpinProber,
    DetectorType::A2aDetector,
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

/// One open port with the service identifiers observed on it, most specific first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedService {
    pub port: u16,
    pub names: Vec<String>,
}

/// Classify observed services, add agent-like signals, and halve confidence when
/// every service is non-agent infrastructure and nothing corroborates the agent.
pub fn apply_services(
    agent: &mut DetectedAgent,
    services: &[ObservedService],
    detector: DetectorType,
    signal_type: &str,
) {
    // ponytail: no observations means the tool saw nothing, not that the host is benign.
    if services.is_empty() {
        return;
    }
    let mut has_agent_like = false;
    let mut all_non_agent = true;

    for svc in services {
        let classes: Vec<ServiceClass> = svc.names.iter().map(|n| classify_service(n)).collect();
        if classes.contains(&ServiceClass::AgentLike) {
            has_agent_like = true;
            all_non_agent = false;
            let label = svc
                .names
                .iter()
                .find(|n| classify_service(n) == ServiceClass::AgentLike)
                .map(String::as_str)
                .unwrap_or("unknown");
            agent.signals.push(Signal::new(
                detector,
                signal_type.to_string(),
                format!("Agent-like service detected on port {}: {label}", svc.port),
                Confidence::Medium,
                serde_json::json!({ "port": svc.port, "names": svc.names }),
            ));
        } else if !classes.contains(&ServiceClass::NonAgent) {
            all_non_agent = false;
        }
    }

    let has_corroborating = agent
        .signals
        .iter()
        .any(|s| CORROBORATING_DETECTORS.contains(&s.detector));
    // Carried over from the Nmap enricher. update_status() recomputes the score
    // from signals, so this reduction does not currently persist.
    if all_non_agent && !has_agent_like && !has_corroborating {
        agent.confidence_score *= 0.5;
    }
    agent.update_status();
}

/// Push `name` unless it is empty or already present.
fn push_unique(names: &mut Vec<String>, name: String) {
    if !name.is_empty() && !names.contains(&name) {
        names.push(name);
    }
}

/// Parse naabu `-json` lines into `(ip, port)` pairs. naabu may repeat a port.
pub fn parse_naabu_json(output: &str) -> Vec<(String, u16)> {
    let mut seen = HashSet::new();
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|v| {
            let ip = v.get("ip")?.as_str()?.to_string();
            let port = u16::try_from(v.get("port")?.as_u64()?).ok()?;
            Some((ip, port))
        })
        .filter(|pair| seen.insert(pair.clone()))
        .collect()
}

/// Parse httpx `-json` lines into `(ip, service)` pairs, one per responding port.
pub fn parse_httpx_json(output: &str) -> Vec<(String, ObservedService)> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| !v.get("failed").and_then(|f| f.as_bool()).unwrap_or(false))
        .filter_map(|v| {
            let ip = v
                .get("host_ip")
                .or_else(|| v.get("host"))?
                .as_str()?
                .to_string();
            // httpx emits the port as a string.
            let port = match v.get("port")? {
                serde_json::Value::String(s) => s.parse().ok()?,
                other => u16::try_from(other.as_u64()?).ok()?,
            };
            let mut names = Vec::new();
            for tech in v
                .get("tech")
                .and_then(|t| t.as_array())
                .into_iter()
                .flatten()
            {
                // Tech names carry an optional ":version" ("Nginx:1.25").
                if let Some(t) = tech.as_str() {
                    let base = t.split(':').next().unwrap_or("").to_lowercase();
                    push_unique(&mut names, base);
                }
            }
            // Server headers list "product/version" tokens ("CUPS/2.4 IPP/2.1").
            if let Some(server) = v.get("webserver").and_then(|s| s.as_str()) {
                for token in server.split_whitespace() {
                    let product = token.split('/').next().unwrap_or("").to_lowercase();
                    push_unique(&mut names, product);
                }
            }
            push_unique(&mut names, "http".to_string());
            Some((ip, ObservedService { port, names }))
        })
        .collect()
}

/// Parse zgrab2 `multiple` output: each module that reports `success` names the service.
pub fn parse_zgrab2_json(output: &str) -> Vec<(String, ObservedService)> {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|v| {
            let ip = v.get("ip")?.as_str()?.to_string();
            let data = v.get("data")?.as_object()?;
            let mut port = v.get("port").and_then(|p| p.as_u64());
            let mut names = Vec::new();
            for (module, result) in data {
                if result.get("status").and_then(|s| s.as_str()) == Some("success") {
                    names.push(module.to_lowercase());
                    port = port.or_else(|| result.get("port").and_then(|p| p.as_u64()));
                }
            }
            let port = u16::try_from(port?).ok()?;
            Some((ip, ObservedService { port, names }))
        })
        .collect()
}

/// Run a tool, feed it stdin, and return at most `MAX_TOOL_OUTPUT_BYTES` of stdout.
/// Returns `Ok(None)` when the binary is not installed.
async fn run_tool(
    bin: &str,
    args: &[&str],
    stdin: String,
    timeout: Duration,
) -> anyhow::Result<Option<String>> {
    let mut cmd = tokio::process::Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for var in PDCP_ENV {
        cmd.env_remove(var);
    }
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut child_stdin = child.stdin.take().expect("stdin piped");
    let stdout = child.stdout.take().expect("stdout piped");

    let run = async move {
        child_stdin.write_all(stdin.as_bytes()).await?;
        drop(child_stdin);
        let mut buf = Vec::new();
        stdout
            .take(MAX_TOOL_OUTPUT_BYTES)
            .read_to_end(&mut buf)
            .await?;
        child.wait().await?;
        Ok::<_, anyhow::Error>(String::from_utf8_lossy(&buf).into_owned())
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| anyhow::anyhow!("{bin} timed out after {}s", timeout.as_secs()))?
        .map(Some)
}

/// zgrab2 `multiple` config with a per-target timeout for every module.
fn zgrab2_config() -> String {
    ZGRAB2_MODULES
        .iter()
        .map(|m| format!("[{m}]\ntarget-timeout=\"5s\"\n"))
        .collect()
}

/// Enricher that runs naabu, httpx and zgrab2 against already-detected agents.
pub struct ServiceEnricher {
    timeout: Duration,
}

impl ServiceEnricher {
    /// `timeout_secs` bounds each tool run.
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// `known` holds the ports agents were detected on. They are always
    /// fingerprinted, even when naabu's top ports miss them (e.g. 11434).
    async fn observe(
        &self,
        ips: &[String],
        known: &[(String, u16)],
    ) -> anyhow::Result<BTreeMap<String, Vec<ObservedService>>> {
        let mut by_ip: BTreeMap<String, BTreeMap<u16, Vec<String>>> = BTreeMap::new();

        // 1. Ports. Connect scan (-s c) works without CAP_NET_RAW; never -nmap.
        let naabu_out = run_tool(
            "naabu",
            &[
                "-json",
                "-silent",
                "-duc",
                "-s",
                "c",
                "-tp",
                NAABU_TOP_PORTS,
            ],
            ips.join("\n"),
            self.timeout,
        )
        .await?
        .unwrap_or_else(|| {
            tracing::warn!("naabu not found; enriching only the ports agents were detected on");
            String::new()
        });
        let mut open = parse_naabu_json(&naabu_out);
        for pair in known {
            if !open.contains(pair) {
                open.push(pair.clone());
            }
        }
        for (ip, port) in &open {
            by_ip
                .entry(ip.clone())
                .or_default()
                .entry(*port)
                .or_default();
        }

        // 2. Web tech on every open port.
        let targets: Vec<String> = open
            .iter()
            .map(|(ip, port)| match ip.contains(':') {
                true => format!("[{ip}]:{port}"),
                false => format!("{ip}:{port}"),
            })
            .collect();
        let mut http_ports = HashSet::new();
        if !targets.is_empty() {
            match run_tool(
                "httpx",
                &["-json", "-silent", "-duc", "-td", "-nc"],
                targets.join("\n"),
                self.timeout,
            )
            .await?
            {
                Some(out) => {
                    for (ip, svc) in parse_httpx_json(&out) {
                        http_ports.insert((ip.clone(), svc.port));
                        by_ip
                            .entry(ip)
                            .or_default()
                            .entry(svc.port)
                            .or_default()
                            .extend(svc.names);
                    }
                }
                None => tracing::warn!("httpx not found; skipping web tech detection"),
            }
        }

        // 3. Banners on the remaining non-HTTP ports.
        let rest: Vec<String> = open
            .iter()
            .filter(|pair| !http_ports.contains(*pair))
            .map(|(ip, port)| format!("{ip},,,{port}"))
            .collect();
        if !rest.is_empty() {
            let config_path = std::env::temp_dir()
                .join(format!("agentsniff-zgrab2-{}.ini", uuid::Uuid::new_v4()));
            std::fs::write(&config_path, zgrab2_config())?;
            let config_arg = config_path.to_string_lossy().into_owned();
            let result = run_tool(
                "zgrab2",
                &[
                    "multiple",
                    "-c",
                    &config_arg,
                    "-b",
                    "/dev/null",
                    "-l",
                    "/dev/null",
                    "-m",
                    "/dev/null",
                    "-u",
                    "/dev/null",
                ],
                rest.join("\n"),
                self.timeout,
            )
            .await;
            let _ = std::fs::remove_file(&config_path);
            match result? {
                Some(out) => {
                    for (ip, svc) in parse_zgrab2_json(&out) {
                        by_ip
                            .entry(ip)
                            .or_default()
                            .entry(svc.port)
                            .or_default()
                            .extend(svc.names);
                    }
                }
                None => tracing::warn!("zgrab2 not found; skipping banner detection"),
            }
        }

        Ok(by_ip
            .into_iter()
            .map(|(ip, ports)| {
                let services = ports
                    .into_iter()
                    .map(|(port, names)| ObservedService { port, names })
                    .collect();
                (ip, services)
            })
            .collect())
    }
}

#[async_trait]
impl Enricher for ServiceEnricher {
    async fn enrich(&self, mut agents: Vec<DetectedAgent>) -> anyhow::Result<Vec<DetectedAgent>> {
        let mut ips: Vec<String> = agents.iter().map(|a| a.ip_address.to_string()).collect();
        ips.sort();
        ips.dedup();
        if ips.is_empty() {
            return Ok(agents);
        }
        let known: Vec<(String, u16)> = agents
            .iter()
            .filter_map(|a| Some((a.ip_address.to_string(), a.port?)))
            .collect();
        let observed = self.observe(&ips, &known).await?;
        for agent in &mut agents {
            let Some(services) = observed.get(&agent.ip_address.to_string()) else {
                continue;
            };
            let json: Vec<serde_json::Value> = services
                .iter()
                .map(|s| serde_json::json!({ "port": s.port, "names": s.names }))
                .collect();
            if let Some(obj) = agent.metadata.as_object_mut() {
                obj.insert("enrich_services".to_string(), serde_json::json!(json));
            }
            apply_services(
                agent,
                services,
                DetectorType::ServiceEnricher,
                "service_match",
            );
        }
        Ok(agents)
    }
}
