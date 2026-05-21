use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

/// Ports to probe for HTTP-based agent endpoints.
pub const PROBE_PORTS: &[u16] = &[
    80, 443, 3000, 3001, 3080, 3100, 5000, 8000, 8001, 8080, 8501, 11434,
];

/// Well-known metadata paths that indicate AI agent presence.
const METADATA_PATHS: &[&str] = &[
    "/.well-known/agents.json",
    "/.well-known/ai-plugin.json",
    "/.well-known/clawhub.json",
    "/.well-known/agent-identity.json",
    "/AGENTS.md",
    "/SKILL.md",
    "/SOUL.md",
    "/MEMORY.md",
];

/// OpenAPI / documentation paths.
const OPENAPI_PATHS: &[&str] = &["/openapi.json", "/docs", "/swagger.json", "/api-docs"];

/// Strong AI-specific keywords used to filter generic OpenAPI specs and
/// markdown documents. Intentionally narrow — generic terms like "agent",
/// "chat", or "workflow" produce false positives against Pi-hole, Gitea,
/// n8n and any SPA that returns 200 for unknown paths.
const AI_KEYWORDS: &[&str] = &[
    "llm",
    "large language model",
    "completion",
    "/completions",
    "/v1/completions",
    "embedding",
    "/embeddings",
    "langchain",
    "autogen",
    "crewai",
    "tool_call",
    "function_call",
    "inference",
    "/v1/inference",
    "mcp",
    "model context protocol",
    "rag",
    "retrieval augmented",
    "openai",
    "anthropic",
    "huggingface",
    "ollama",
    "vllm",
    "llamacpp",
    "langserve",
    "langgraph",
];

/// Subset of [`AI_KEYWORDS`] used to validate agent markdown documents.
const MD_KEYWORDS: &[&str] = &[
    "llm",
    "large language model",
    "ai agent",
    "mcp",
    "model context protocol",
    "langchain",
    "autogen",
    "crewai",
    "tool_call",
    "function_call",
];

/// A framework signature loaded from the signed `frameworks.json` overlay.
#[derive(Debug, Clone, Default)]
struct FrameworkSig {
    name: String,
    endpoints: Vec<String>,
    headers: Vec<String>,
    user_agents: Vec<String>,
}

impl FrameworkSig {
    fn from_json(name: &str, value: &Value) -> Self {
        let mut sig = FrameworkSig {
            name: name.to_string(),
            ..Default::default()
        };
        if let Some(eps) = value.get("endpoints").and_then(|v| v.as_array()) {
            sig.endpoints = eps
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(hs) = value.get("headers").and_then(|v| v.as_array()) {
            sig.headers = hs
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect();
        }
        if let Some(ua) = value.get("user_agents").and_then(|v| v.as_array()) {
            sig.user_agents = ua
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect();
        }
        sig
    }
}

/// Endpoint prober detector that fingerprints AI agent frameworks via HTTP probing.
pub struct EndpointProberDetector {
    timeout: Duration,
    concurrency: usize,
    client: reqwest::Client,
    frameworks: BTreeMap<String, FrameworkSig>,
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

        let frameworks = Self::load_frameworks(config);

        Self {
            timeout,
            concurrency: config.http_concurrency,
            client,
            frameworks,
        }
    }

    /// Load framework signatures from the signed overlay, then merge in any
    /// `custom_framework_signatures` from the YAML config.
    fn load_frameworks(config: &ScanConfig) -> BTreeMap<String, FrameworkSig> {
        let mut out = BTreeMap::new();
        let sigs = SignatureData::load_with_overlay();
        if let Some(obj) = sigs.frameworks.as_object() {
            for (name, value) in obj {
                out.insert(name.clone(), FrameworkSig::from_json(name, value));
            }
        }
        if let Some(obj) = config.custom_framework_signatures.as_object() {
            for (name, value) in obj {
                out.insert(name.clone(), FrameworkSig::from_json(name, value));
            }
        }
        out
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

    /// Probe a single URL path and return the response status, content-type,
    /// headers, and a body snippet (up to 8 KB).
    async fn probe_path(
        &self,
        base: &str,
        path: &str,
    ) -> Option<(u16, String, reqwest::header::HeaderMap, String)> {
        let url = format!("{}{}", base, path);
        let resp = self.client.get(&url).send().await.ok()?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp
            .text()
            .await
            .unwrap_or_default()
            .chars()
            .take(8192)
            .collect::<String>();
        Some((status, content_type, headers, body))
    }

    /// Probe framework endpoints, metadata paths and OpenAPI paths on a single
    /// host:port. Returns a deduplicated signal set.
    async fn probe_host_port(&self, ip: IpAddr, port: u16) -> Vec<Signal> {
        let base = Self::base_url(ip, port);
        let mut signals = Vec::new();

        // --- Framework endpoint probing ---
        for sig in self.frameworks.values() {
            for endpoint in &sig.endpoints {
                let Some((status, _ct, headers, body)) =
                    self.probe_path(&base, endpoint).await
                else {
                    continue;
                };
                if status >= 400 {
                    continue;
                }

                let body_lower = body.to_lowercase();
                let fw_lower = sig.name.to_lowercase().replace('_', "");

                let matched_headers = match_headers(&headers, &sig.headers);
                let has_header = !matched_headers.is_empty();
                // Body must contain the framework name OR one of its
                // user-agent strings. A bare 200 OK from an SPA's catch-all
                // route is NOT evidence of a framework.
                let body_match = body_lower.contains(&fw_lower)
                    || sig
                        .user_agents
                        .iter()
                        .any(|ua| body_lower.contains(ua.as_str()));

                if !has_header && !body_match {
                    continue;
                }

                let confidence = if has_header || body_match {
                    Confidence::High
                } else {
                    Confidence::Medium
                };

                let signal_type = if has_header {
                    "framework_header_match"
                } else {
                    "framework_endpoint_match"
                };

                let description = format!(
                    "{} framework {} match at {}{} (status {})",
                    sig.name,
                    if has_header { "header" } else { "endpoint" },
                    base,
                    endpoint,
                    status,
                );

                let mut evidence = serde_json::json!({
                    "ip": ip.to_string(),
                    "port": port,
                    "framework": sig.name,
                    "endpoint": endpoint,
                    "status_code": status,
                    "body_match": body_match,
                    "matched_headers": matched_headers,
                });
                if !body.is_empty() {
                    evidence["content_sample"] = serde_json::Value::String(
                        body.chars().take(500).collect(),
                    );
                }

                signals.push(Signal::new(
                    DetectorType::EndpointProber,
                    signal_type.to_string(),
                    description,
                    confidence,
                    evidence,
                ));

                // One signal per framework is enough.
                break;
            }
        }

        // --- Metadata path probing ---
        for &path in METADATA_PATHS {
            let Some((status, _ct, _headers, body)) =
                self.probe_path(&base, path).await
            else {
                continue;
            };
            if status != 200 || body.len() < 10 {
                continue;
            }

            let mut is_valid = false;
            let mut metadata_type = "unknown";
            let mut confidence = Confidence::High;

            if path.ends_with(".json") {
                match serde_json::from_str::<Value>(&body) {
                    Ok(Value::Object(doc)) => {
                        if doc.get("agents").and_then(|v| v.as_array()).is_some() {
                            is_valid = true;
                            metadata_type = "agent_directory";
                            confidence = Confidence::Confirmed;
                        } else if doc.contains_key("name_for_model")
                            || doc.contains_key("description_for_model")
                            || (doc.contains_key("schema_version")
                                && doc.contains_key("name_for_human"))
                        {
                            is_valid = true;
                            metadata_type = "ai_plugin";
                            confidence = Confidence::Confirmed;
                        }
                    }
                    _ => continue, // not valid JSON → not metadata
                }
            } else if path.ends_with(".md") {
                let body_lower = body.to_lowercase();
                let hits = MD_KEYWORDS
                    .iter()
                    .filter(|kw| body_lower.contains(*kw))
                    .count();
                if hits >= 2 {
                    is_valid = true;
                    metadata_type = "agent_markdown";
                    confidence = Confidence::High;
                }
            }

            if !is_valid {
                continue;
            }

            let url = format!("{}{}", base, path);
            signals.push(Signal::new(
                DetectorType::EndpointProber,
                "agent_metadata_found".to_string(),
                format!(
                    "Agent metadata document at {} (type: {})",
                    url, metadata_type
                ),
                confidence,
                serde_json::json!({
                    "ip": ip.to_string(),
                    "port": port,
                    "path": path,
                    "metadata_type": metadata_type,
                    "content_length": body.len(),
                    "content_sample": body.chars().take(500).collect::<String>(),
                }),
            ));
        }

        // --- OpenAPI path probing ---
        for &path in OPENAPI_PATHS {
            let Some((status, content_type, _headers, body)) =
                self.probe_path(&base, path).await
            else {
                continue;
            };
            if status != 200 || body.len() < 20 {
                continue;
            }

            let mut is_openapi = false;
            let mut is_ai_api = false;
            let mut title = String::from("unknown");

            if content_type.contains("json") || path.ends_with(".json") {
                if let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(&body) {
                    if doc.contains_key("openapi") || doc.contains_key("swagger") {
                        is_openapi = true;
                        title = doc
                            .get("info")
                            .and_then(|v| v.get("title"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        let description = doc
                            .get("info")
                            .and_then(|v| v.get("description"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let paths_joined = doc
                            .get("paths")
                            .and_then(|v| v.as_object())
                            .map(|m| m.keys().cloned().collect::<Vec<_>>().join(" "))
                            .unwrap_or_default();
                        let searchable = format!(
                            "{} {} {}",
                            title.to_lowercase(),
                            description.to_lowercase(),
                            paths_joined.to_lowercase()
                        );
                        is_ai_api = AI_KEYWORDS.iter().any(|kw| searchable.contains(kw));
                    }
                }
            } else if content_type.contains("html") {
                let body_lower = body.to_lowercase();
                if body_lower.contains("swagger")
                    || body_lower.contains("openapi")
                    || body_lower.contains("redoc")
                    || body_lower.contains("rapidoc")
                {
                    is_openapi = true;
                    is_ai_api = AI_KEYWORDS.iter().any(|kw| body_lower.contains(kw));
                }
            }

            if !is_openapi {
                continue;
            }

            // HIGH only if the spec actually references AI/agent concepts;
            // generic API specs (Gitea, n8n, etc.) stay LOW so fusion can
            // suppress them when no corroborating signal exists.
            let confidence = if is_ai_api {
                Confidence::High
            } else {
                Confidence::Low
            };

            let url = format!("{}{}", base, path);
            signals.push(Signal::new(
                DetectorType::EndpointProber,
                "agent_openapi_spec".to_string(),
                format!("OpenAPI spec at {} (title: {})", url, title),
                confidence,
                serde_json::json!({
                    "ip": ip.to_string(),
                    "port": port,
                    "path": path,
                    "title": title,
                    "ai_related": is_ai_api,
                    "content_type": content_type,
                }),
            ));
        }

        deduplicate(signals)
    }
}

/// Match response headers against a list of patterns (case-insensitive).
/// Trailing `*` indicates a prefix wildcard.
fn match_headers(
    resp_headers: &reqwest::header::HeaderMap,
    expected: &[String],
) -> Vec<String> {
    let mut matched = Vec::new();
    let names: Vec<String> = resp_headers
        .keys()
        .map(|k| k.as_str().to_lowercase())
        .collect();

    for pattern in expected {
        if let Some(prefix) = pattern.strip_suffix('*') {
            for name in &names {
                if name.starts_with(prefix) {
                    matched.push(name.clone());
                }
            }
        } else if names.iter().any(|n| n == pattern) {
            matched.push(pattern.clone());
        }
    }
    matched
}

/// Remove duplicate signals, keeping the highest-confidence entry per
/// (host, port, framework_or_path, signal_type) key.
fn deduplicate(signals: Vec<Signal>) -> Vec<Signal> {
    let mut best: BTreeMap<(String, u64, String, String), Signal> = BTreeMap::new();
    let rank = |c: Confidence| match c {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
        Confidence::Confirmed => 3,
    };

    for sig in signals {
        let host = sig
            .evidence
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let port = sig
            .evidence
            .get("port")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let key_third = sig
            .evidence
            .get("framework")
            .and_then(|v| v.as_str())
            .or_else(|| sig.evidence.get("path").and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        let key = (host, port, key_third, sig.signal_type.clone());

        let replace = match best.get(&key) {
            None => true,
            Some(existing) => rank(sig.confidence) > rank(existing.confidence),
        };
        if replace {
            best.insert(key, sig);
        }
    }

    best.into_values().collect()
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
                let frameworks = self.frameworks.clone();

                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let detector = EndpointProberDetector {
                        timeout,
                        concurrency,
                        client,
                        frameworks,
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

        Ok(deduplicate(signals))
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
