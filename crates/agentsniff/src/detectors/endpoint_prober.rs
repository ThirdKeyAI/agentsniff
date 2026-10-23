use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::ScanConfig;
use crate::http::read_body_prefix_limited;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

/// Framework matching uses at most the first 8 KiB. A larger transport cap
/// allows ordinary headers/spec prefixes while bounding hostile responses.
const MAX_ENDPOINT_RESPONSE_BYTES: usize = 64 * 1024;

/// Ports to probe for HTTP-based agent endpoints.
pub const PROBE_PORTS: &[u16] = &[
    80, 443, 3000, 3001, 3080, 3100, 5000, 8000, 8001, 8080, 8501, 11434,
];

/// Well-known metadata paths that indicate AI agent presence.
const METADATA_PATHS: &[&str] = &[
    "/.well-known/agents.json",
    "/.well-known/ai-plugin.json",
    "/.well-known/clawhub.json",
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
    probe_paths: Vec<String>,
    response_header_names: Vec<String>,
    response_headers: BTreeMap<String, Vec<String>>,
    response_body_markers: Vec<String>,
    json_predicates: Vec<JsonPredicate>,
    // Passive-only indicators are retained in the parsed schema rather than
    // incorrectly searching for request User-Agent values in response bodies.
    #[allow(dead_code)]
    request_user_agents: Vec<String>,
    #[allow(dead_code)]
    mcp_client_names: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct JsonPredicate {
    path: String,
    exists: bool,
    equals: Option<Value>,
}

impl FrameworkSig {
    fn from_json(name: &str, value: &Value) -> Self {
        let mut sig = FrameworkSig {
            name: name.to_string(),
            ..Default::default()
        };
        for field in ["probe_paths", "well_known_paths", "endpoints"] {
            match value.get(field) {
                Some(Value::Array(paths)) => sig
                    .probe_paths
                    .extend(paths.iter().filter_map(Value::as_str).map(String::from)),
                Some(Value::String(path)) => sig.probe_paths.push(path.clone()),
                _ => {}
            }
        }
        for field in ["response_header_names", "headers"] {
            if let Some(headers) = value.get(field).and_then(Value::as_array) {
                sig.response_header_names.extend(
                    headers
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_ascii_lowercase),
                );
            }
        }
        if let Some(headers) = value.get("response_headers").and_then(Value::as_object) {
            for (name, patterns) in headers {
                let patterns = match patterns {
                    Value::String(pattern) => vec![pattern.to_ascii_lowercase()],
                    Value::Array(patterns) => patterns
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_ascii_lowercase)
                        .collect(),
                    _ => Vec::new(),
                };
                sig.response_headers
                    .insert(name.to_ascii_lowercase(), patterns);
            }
        }
        if let Some(markers) = value.get("response_body_markers").and_then(Value::as_array) {
            sig.response_body_markers = markers
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect();
        }
        for field in ["request_user_agents", "user_agents"] {
            if let Some(values) = value.get(field).and_then(Value::as_array) {
                sig.request_user_agents.extend(
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_ascii_lowercase),
                );
            }
        }
        match value.get("mcp_client_names") {
            Some(Value::Array(values)) => sig.mcp_client_names.extend(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_ascii_lowercase),
            ),
            Some(Value::String(name)) => sig.mcp_client_names.push(name.to_ascii_lowercase()),
            _ => {}
        }
        if let Some(name) = value.get("mcp_client_name").and_then(Value::as_str) {
            sig.mcp_client_names.push(name.to_ascii_lowercase());
        }
        if let Some(predicates) = value.get("json_predicates").and_then(Value::as_array) {
            sig.json_predicates = predicates
                .iter()
                .filter_map(|predicate| {
                    let predicate = predicate.as_object()?;
                    Some(JsonPredicate {
                        path: predicate.get("path")?.as_str()?.to_string(),
                        exists: predicate
                            .get("exists")
                            .and_then(Value::as_bool)
                            .unwrap_or(true),
                        equals: predicate.get("equals").cloned(),
                    })
                })
                .collect();
        }
        sig.probe_paths.sort();
        sig.probe_paths.dedup();
        sig
    }
}

/// Match a passively observed MCP `clientInfo.name` against the signed
/// framework catalog. Active endpoint probing cannot observe third-party
/// client names, so callers such as packet/log integrations use this helper.
pub fn match_mcp_client_name(frameworks: &Value, client_name: &str) -> Vec<String> {
    let needle = client_name.to_ascii_lowercase();
    frameworks
        .as_object()
        .into_iter()
        .flat_map(|entries| entries.iter())
        .filter_map(|(framework, value)| {
            let names = value
                .get("mcp_client_names")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .chain(value.get("mcp_client_name").and_then(Value::as_str));
            names
                .into_iter()
                .any(|name| name.eq_ignore_ascii_case(&needle))
                .then(|| framework.clone())
        })
        .collect()
}

/// Match a passively observed HTTP User-Agent without treating it as response
/// body content during active probing.
pub fn match_request_user_agent(frameworks: &Value, user_agent: &str) -> Vec<String> {
    let haystack = user_agent.to_ascii_lowercase();
    frameworks
        .as_object()
        .into_iter()
        .flat_map(|entries| entries.iter())
        .filter_map(|(framework, value)| {
            let markers = value
                .get("request_user_agents")
                .or_else(|| value.get("user_agents"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            markers
                .into_iter()
                .any(|marker| haystack.contains(&marker.to_ascii_lowercase()))
                .then(|| framework.clone())
        })
        .collect()
}

/// Endpoint prober detector that fingerprints AI agent frameworks via HTTP probing.
pub struct EndpointProberDetector {
    timeout: Duration,
    concurrency: usize,
    client: reqwest::Client,
    frameworks: BTreeMap<String, FrameworkSig>,
    ports: Vec<u16>,
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
            ports: config.ports_or(PROBE_PORTS),
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
        crate::ratelimit::acquire().await;
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
        crate::ratelimit::acquire().await;
        let resp = self.client.get(&url).send().await.ok()?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = String::from_utf8_lossy(
            &read_body_prefix_limited(resp, MAX_ENDPOINT_RESPONSE_BYTES)
                .await
                .ok()?,
        )
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
            for endpoint in &sig.probe_paths {
                let Some((status, _ct, headers, body)) = self.probe_path(&base, endpoint).await
                else {
                    continue;
                };
                if status >= 400 {
                    continue;
                }

                let body_lower = body.to_lowercase();
                let fw_lower = sig.name.to_ascii_lowercase();

                let mut matched_headers = match_headers(&headers, &sig.response_header_names);
                matched_headers.extend(match_header_values(&headers, &sig.response_headers));
                matched_headers.sort();
                matched_headers.dedup();
                let has_header = !matched_headers.is_empty();
                let body_match = [
                    fw_lower.clone(),
                    fw_lower.replace('_', "-"),
                    fw_lower.replace('_', " "),
                    fw_lower.replace('_', ""),
                ]
                .iter()
                .any(|marker| body_lower.contains(marker))
                    || sig
                        .response_body_markers
                        .iter()
                        .any(|marker| body_lower.contains(marker));
                let json_match = matches_json_predicates(&body, &sig.json_predicates);

                if !has_header && !body_match && !json_match {
                    continue;
                }

                let confidence = if has_header || body_match || json_match {
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
                    "json_predicates_match": json_match,
                    "matched_headers": matched_headers,
                });
                if !body.is_empty() {
                    evidence["content_sample"] =
                        serde_json::Value::String(body.chars().take(500).collect());
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
            let Some((status, _ct, _headers, body)) = self.probe_path(&base, path).await else {
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
                            // A directory is self-asserted metadata, not a
                            // cryptographically authenticated identity.
                            confidence = Confidence::High;
                        } else if doc.contains_key("name_for_model")
                            || doc.contains_key("description_for_model")
                            || (doc.contains_key("schema_version")
                                && doc.contains_key("name_for_human"))
                        {
                            is_valid = true;
                            metadata_type = "ai_plugin";
                            confidence = Confidence::High;
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
            let Some((status, content_type, _headers, body)) = self.probe_path(&base, path).await
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
fn match_headers(resp_headers: &reqwest::header::HeaderMap, expected: &[String]) -> Vec<String> {
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

fn match_header_values(
    resp_headers: &reqwest::header::HeaderMap,
    expected: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let mut matched = Vec::new();
    for (name, patterns) in expected {
        let candidate_names: Vec<&reqwest::header::HeaderName> =
            if let Some(prefix) = name.strip_suffix('*') {
                resp_headers
                    .keys()
                    .filter(|candidate| candidate.as_str().starts_with(prefix))
                    .collect()
            } else {
                resp_headers
                    .keys()
                    .filter(|candidate| candidate.as_str().eq_ignore_ascii_case(name))
                    .collect()
            };
        for candidate_name in candidate_names {
            let value = resp_headers
                .get(candidate_name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase();
            if patterns.is_empty()
                || patterns
                    .iter()
                    .any(|pattern| wildcard_value_match(&value, pattern))
            {
                matched.push(candidate_name.as_str().to_string());
            }
        }
    }
    matched
}

fn wildcard_value_match(value: &str, pattern: &str) -> bool {
    match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
        (Some(rest), _) if rest.ends_with('*') => value.contains(rest.trim_end_matches('*')),
        (Some(suffix), _) => value.ends_with(suffix),
        (_, Some(prefix)) => value.starts_with(prefix),
        _ => value == pattern,
    }
}

fn matches_json_predicates(body: &str, predicates: &[JsonPredicate]) -> bool {
    if predicates.is_empty() {
        return false;
    }
    let Ok(document) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    predicates.iter().all(|predicate| {
        let found = predicate
            .path
            .split('.')
            .filter(|part| !part.is_empty())
            .try_fold(&document, |current, part| current.get(part));
        if !predicate.exists {
            return found.is_none();
        }
        match (&predicate.equals, found) {
            (_, None) => false,
            (Some(expected), Some(actual)) => actual == expected,
            (None, Some(_)) => true,
        }
    })
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

        // Probe all (host, port) pairs concurrently — sequential per-port
        // probing across a /24 turned this detector into a 25-minute loop.
        let mut probe_handles: Vec<tokio::task::JoinHandle<(IpAddr, u16, bool)>> = Vec::new();
        for &ip in targets {
            for &port in &self.ports {
                let permit = semaphore.clone().acquire_owned().await?;
                probe_handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    (ip, port, Self::is_port_open(ip, port).await)
                }));
            }
        }
        let mut open_by_host: std::collections::HashMap<IpAddr, Vec<u16>> =
            std::collections::HashMap::new();
        for h in probe_handles {
            if let Ok((ip, port, open)) = h.await {
                if open {
                    open_by_host.entry(ip).or_default().push(port);
                }
            }
        }

        for (ip, open_ports) in open_by_host {
            if open_ports.is_empty() {
                continue;
            }

            for port in open_ports {
                let permit = semaphore.clone().acquire_owned().await?;
                let client = self.client.clone();
                let timeout = self.timeout;
                let concurrency = self.concurrency;
                let frameworks = self.frameworks.clone();
                let ports = self.ports.clone();

                let handle = tokio::spawn(async move {
                    let _permit = permit;
                    let detector = EndpointProberDetector {
                        timeout,
                        concurrency,
                        client,
                        frameworks,
                        ports,
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
