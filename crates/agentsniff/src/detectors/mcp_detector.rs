use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::HeaderMap;
use reqwest::Client;
use serde_json::Value;

use crate::config::ScanConfig;
use crate::http::read_body_limited;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

const MCP_PATHS: &[&str] = &[
    "/mcp", "/sse", "/events", "/mcp/sse", "/message", "/jsonrpc", "/rpc", "/api/mcp", "/v1/mcp",
];
const DEFAULT_MCP_PORTS: &[u16] = &[80, 443, 3000, 3001, 5000, 6274, 8000, 8001, 8080, 9000];
const MAX_MCP_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
struct McpProtocolSignature {
    version: String,
    discovery_method: String,
    methods: Vec<String>,
}

#[derive(Debug, Clone)]
struct AgentpinMcpBinding {
    capability_path: String,
    credential_meta_key: String,
    version: String,
}

pub fn build_jsonrpc_request(method: &str, params: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
}

pub fn is_valid_jsonrpc_response(body: &Value) -> bool {
    body.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && body.get("id").is_some()
        && body.get("result").is_some()
        && body.get("error").is_none()
}

/// Parse plain JSON or the first JSON `data:` item in an SSE response.
pub fn parse_json_or_sse(bytes: &[u8]) -> Option<Value> {
    if let Ok(value) = serde_json::from_slice(bytes) {
        return Some(value);
    }
    let text = std::str::from_utf8(bytes).ok()?;
    text.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|payload| !payload.is_empty() && *payload != "[DONE]")
        .find_map(|payload| serde_json::from_str(payload).ok())
}

/// Return an advertised AgentPin MCP capability from a JSON-RPC result.
///
/// The path comes from the signed MCP catalog so protocol extensions can be
/// updated without hard-coding response structure in the detector.
pub fn agentpin_capability<'a>(result: &'a Value, capability_path: &str) -> Option<&'a Value> {
    let value = capability_path
        .split('.')
        .try_fold(result, |current, segment| current.get(segment))?;
    value.is_object().then_some(value)
}

fn load_agentpin_binding(data: &Value) -> Option<AgentpinMcpBinding> {
    let binding = data
        .get("extensions")?
        .get("org.agentpin/credential-binding")?;
    Some(AgentpinMcpBinding {
        capability_path: binding.get("capability_path")?.as_str()?.to_string(),
        credential_meta_key: binding.get("credential_meta_key")?.as_str()?.to_string(),
        version: binding.get("version")?.as_str()?.to_string(),
    })
}

fn load_protocol_signatures(data: &Value) -> Vec<McpProtocolSignature> {
    let Some(protocols) = data.get("protocols").and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut by_version = BTreeMap::new();
    for (version, value) in protocols {
        let Some(discovery_method) = value.get("discovery_method").and_then(Value::as_str) else {
            continue;
        };
        let methods = value
            .get("methods")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect();
        by_version.insert(
            version.clone(),
            McpProtocolSignature {
                version: version.clone(),
                discovery_method: discovery_method.to_string(),
                methods,
            },
        );
    }

    let mut ordered = Vec::new();
    if let Some(preferred) = data.get("preferred_order").and_then(Value::as_array) {
        for version in preferred.iter().filter_map(Value::as_str) {
            if let Some(protocol) = by_version.remove(version) {
                ordered.push(protocol);
            }
        }
    }
    ordered.extend(by_version.into_values().rev());
    ordered
}

fn load_mcp_ports(signatures: &SignatureData) -> Vec<u16> {
    let mut ports = DEFAULT_MCP_PORTS.to_vec();
    for (&port, services) in &signatures.ports {
        if services
            .iter()
            .any(|service| service.to_ascii_lowercase().contains("mcp"))
        {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[derive(Clone)]
pub struct McpDetector {
    client: Client,
    protocols: Vec<McpProtocolSignature>,
    ports: Vec<u16>,
    agentpin_binding: Option<AgentpinMcpBinding>,
}

impl McpDetector {
    pub fn new(config: &ScanConfig) -> Self {
        let timeout = Duration::from_secs_f64(config.http_timeout);
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build reqwest client");

        let signatures = SignatureData::load_with_overlay();
        let protocols = load_protocol_signatures(&signatures.mcp_methods);
        if protocols.is_empty() {
            tracing::error!("signed MCP protocol catalog unavailable; MCP probing disabled");
        }
        let ports = config.ports_or(&load_mcp_ports(&signatures));
        let agentpin_binding = load_agentpin_binding(&signatures.mcp_methods);
        Self {
            client,
            protocols,
            ports,
            agentpin_binding,
        }
    }

    pub fn supported_protocols(&self) -> Vec<&str> {
        self.protocols
            .iter()
            .map(|protocol| protocol.version.as_str())
            .collect()
    }

    async fn send_jsonrpc_with(
        client: &Client,
        url: &str,
        method: &str,
        version: &str,
        session_id: Option<&str>,
        body: &Value,
    ) -> Option<(Value, HeaderMap)> {
        let mut request = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", version)
            .header("Mcp-Method", method);
        if let Some(session_id) = session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }
        crate::ratelimit::acquire().await;
        let response = request.json(body).send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let headers = response.headers().clone();
        let bytes = read_body_limited(response, MAX_MCP_RESPONSE_BYTES)
            .await
            .ok()?;
        Some((parse_json_or_sse(&bytes)?, headers))
    }

    async fn send_initialized_notification(
        client: &Client,
        url: &str,
        version: &str,
        session_id: Option<&str>,
    ) {
        let mut request = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", version)
            .header("Mcp-Method", "notifications/initialized");
        if let Some(session_id) = session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }
        crate::ratelimit::acquire().await;
        let _ = request
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }))
            .send()
            .await;
    }

    fn discovery_request(protocol: &McpProtocolSignature) -> Value {
        if protocol.discovery_method == "initialize" {
            build_jsonrpc_request(
                "initialize",
                serde_json::json!({
                    "protocolVersion": protocol.version,
                    "capabilities": {},
                    "clientInfo": {"name": "agentsniff", "version": env!("CARGO_PKG_VERSION")}
                }),
            )
        } else {
            build_jsonrpc_request(&protocol.discovery_method, serde_json::json!({}))
        }
    }

    async fn probe_one(&self, ip: IpAddr, port: u16, path: &'static str) -> Vec<Signal> {
        let scheme = if port == 443 { "https" } else { "http" };
        let host = if ip.is_ipv6() {
            format!("[{}]", ip)
        } else {
            ip.to_string()
        };
        let url = format!("{}://{}:{}{}", scheme, host, port, path);

        for protocol in &self.protocols {
            let request = Self::discovery_request(protocol);
            let Some((body, headers)) = Self::send_jsonrpc_with(
                &self.client,
                &url,
                &protocol.discovery_method,
                &protocol.version,
                None,
                &request,
            )
            .await
            else {
                continue;
            };
            if !is_valid_jsonrpc_response(&body) {
                continue;
            }

            let response_version = headers
                .get("MCP-Protocol-Version")
                .and_then(|value| value.to_str().ok())
                .or_else(|| {
                    body.get("result")
                        .and_then(|result| result.get("protocolVersion"))
                        .and_then(Value::as_str)
                });
            let version_confirmed = response_version == Some(protocol.version.as_str());
            let confidence = if version_confirmed {
                Confidence::Confirmed
            } else {
                Confidence::High
            };
            let session_id = headers
                .get("Mcp-Session-Id")
                .and_then(|value| value.to_str().ok());

            if protocol.discovery_method == "initialize" {
                Self::send_initialized_notification(
                    &self.client,
                    &url,
                    &protocol.version,
                    session_id,
                )
                .await;
            }

            let result = body.get("result").cloned().unwrap_or(Value::Null);
            let server_info = result
                .get("serverInfo")
                .or_else(|| result.get("server"))
                .cloned()
                .unwrap_or(Value::Null);
            let capabilities = result
                .get("capabilities")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));

            let mut signals = vec![Signal::new(
                DetectorType::McpDetector,
                "mcp_server_confirmed".to_string(),
                format!(
                    "MCP {} server detected on {}:{}{}",
                    protocol.version, ip, port, path
                ),
                confidence,
                serde_json::json!({
                    "ip": ip.to_string(),
                    "port": port,
                    "path": path,
                    "protocol_version": protocol.version,
                    "discovery_method": protocol.discovery_method,
                    "server_info": server_info,
                    "capabilities": capabilities,
                    "version_confirmed_by_server": version_confirmed,
                    "session_established": session_id.is_some(),
                }),
            )];

            if let Some(binding) = &self.agentpin_binding {
                if let Some(advertised) = agentpin_capability(&result, &binding.capability_path) {
                    let advertised_version = advertised.get("version").and_then(Value::as_str);
                    let required = advertised
                        .get("required")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    signals.push(Signal::new(
                        DetectorType::McpDetector,
                        "mcp_agentpin_binding_advertised".to_string(),
                        format!(
                            "MCP server on {}:{}{} advertises AgentPin credential binding{}",
                            ip,
                            port,
                            path,
                            advertised_version
                                .map(|version| format!(" version {version}"))
                                .unwrap_or_default()
                        ),
                        Confidence::High,
                        serde_json::json!({
                            "ip": ip.to_string(),
                            "port": port,
                            "path": path,
                            "protocol_version": protocol.version,
                            "capability_path": binding.capability_path,
                            "credential_meta_key": binding.credential_meta_key,
                            "expected_binding_version": binding.version,
                            "advertised_binding": advertised,
                            "binding_version_matches": advertised_version == Some(binding.version.as_str()),
                            "required": required,
                            "identity_verified": false,
                            "credential_observed": false,
                        }),
                    ));
                }
            }

            signals.extend(
                Self::enumerate_capabilities_with(
                    &self.client,
                    &url,
                    ip,
                    port,
                    path,
                    protocol,
                    session_id,
                )
                .await,
            );
            return signals;
        }
        Vec::new()
    }

    async fn enumerate_capabilities_with(
        client: &Client,
        url: &str,
        ip: IpAddr,
        port: u16,
        path: &str,
        protocol: &McpProtocolSignature,
        session_id: Option<&str>,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();
        for (method, result_key, signal_type, label) in [
            ("tools/list", "tools", "mcp_tools_enumerated", "tools"),
            (
                "resources/list",
                "resources",
                "mcp_resources_enumerated",
                "resources",
            ),
            (
                "prompts/list",
                "prompts",
                "mcp_prompts_enumerated",
                "prompts",
            ),
        ] {
            if !protocol.methods.iter().any(|candidate| candidate == method) {
                continue;
            }
            let request = build_jsonrpc_request(method, serde_json::json!({}));
            let Some((body, _)) = Self::send_jsonrpc_with(
                client,
                url,
                method,
                &protocol.version,
                session_id,
                &request,
            )
            .await
            else {
                continue;
            };
            if !is_valid_jsonrpc_response(&body) {
                continue;
            }
            let items = body
                .get("result")
                .and_then(|result| result.get(result_key))
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            signals.push(Signal::new(
                DetectorType::McpDetector,
                signal_type.to_string(),
                format!(
                    "MCP {} enumerated on {}:{}{} ({} {})",
                    label,
                    ip,
                    port,
                    path,
                    items.as_array().map_or(0, Vec::len),
                    label
                ),
                Confidence::High,
                serde_json::json!({
                    "ip": ip.to_string(),
                    "port": port,
                    "path": path,
                    "protocol_version": protocol.version,
                    result_key: items,
                }),
            ));
        }
        signals
    }

    async fn is_port_open(ip: IpAddr, port: u16) -> bool {
        let addr = std::net::SocketAddr::new(ip, port);
        crate::ratelimit::acquire().await;
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .is_ok_and(|result| result.is_ok())
    }
}

#[async_trait]
impl Detector for McpDetector {
    fn name(&self) -> &str {
        "mcp_detector"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::McpDetector
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        use tokio::sync::Semaphore;

        let connect_sem = std::sync::Arc::new(Semaphore::new(256));
        let mut connect_handles = Vec::new();
        for &ip in targets {
            for &port in &self.ports {
                let permit = connect_sem.clone().acquire_owned().await?;
                connect_handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    (ip, port, Self::is_port_open(ip, port).await)
                }));
            }
        }

        let mut open_pairs = Vec::new();
        for handle in connect_handles {
            if let Ok((ip, port, true)) = handle.await {
                open_pairs.push((ip, port));
            }
        }
        if open_pairs.is_empty() {
            return Ok(Vec::new());
        }

        let rpc_sem = std::sync::Arc::new(Semaphore::new(64));
        let mut rpc_handles = Vec::new();
        for (ip, port) in open_pairs {
            let permit = rpc_sem.clone().acquire_owned().await?;
            let detector = self.clone();
            rpc_handles.push(tokio::spawn(async move {
                let _permit = permit;
                for &path in MCP_PATHS {
                    let found = detector.probe_one(ip, port, path).await;
                    if !found.is_empty() {
                        return found;
                    }
                }
                Vec::new()
            }));
        }
        let mut signals = Vec::new();
        for handle in rpc_handles {
            if let Ok(mut found) = handle.await {
                signals.append(&mut found);
            }
        }
        Ok(signals)
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
