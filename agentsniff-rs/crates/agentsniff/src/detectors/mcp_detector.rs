use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};

use super::Detector;

/// URL paths commonly used by MCP servers.
const MCP_PATHS: &[&str] = &[
    "/mcp",
    "/sse",
    "/events",
    "/mcp/sse",
    "/message",
    "/jsonrpc",
    "/rpc",
    "/api/mcp",
    "/v1/mcp",
];

/// Ports commonly used by MCP servers.
const MCP_PORTS: &[u16] = &[3000, 3001, 8080, 8000, 8001, 5000, 9000];

/// Build a JSON-RPC 2.0 request body.
pub fn build_jsonrpc_request(method: &str, params: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
}

/// Validate that a JSON body is a successful JSON-RPC 2.0 response.
///
/// Checks: jsonrpc == "2.0", has "id", has "result" (not "error").
pub fn is_valid_jsonrpc_response(body: &Value) -> bool {
    body.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0")
        && body.get("id").is_some()
        && body.get("result").is_some()
        && body.get("error").is_none()
}

/// MCP (Model Context Protocol) server detector.
pub struct McpDetector {
    #[allow(dead_code)]
    timeout: Duration,
    client: Client,
}

impl McpDetector {
    /// Create a new MCP detector from scan configuration.
    pub fn new(config: &ScanConfig) -> Self {
        let timeout = Duration::from_secs_f64(config.http_timeout);
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build reqwest client");

        Self { timeout, client }
    }

    /// Send a JSON-RPC request to a URL and return the parsed response body.
    async fn send_jsonrpc_with(
        client: &Client,
        url: &str,
        body: &Value,
    ) -> Option<(Value, reqwest::header::HeaderMap)> {
        let resp = client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2024-11-05")
            .json(body)
            .send()
            .await
            .ok()?;

        let headers = resp.headers().clone();
        let json_body = resp.json::<Value>().await.ok()?;
        Some((json_body, headers))
    }

    /// Probe a single (ip, port, path) for an MCP server. Returns any signals
    /// emitted (server confirmation + capability enumeration).
    async fn probe_one(
        client: Client,
        ip: IpAddr,
        port: u16,
        path: &'static str,
    ) -> Vec<Signal> {
        let url = format!("http://{}:{}{}", ip, port, path);
        let init_req = build_jsonrpc_request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "agentsniff",
                    "version": "2.0.0"
                }
            }),
        );

        let (body, headers) = match Self::send_jsonrpc_with(&client, &url, &init_req).await {
            Some(r) => r,
            None => return Vec::new(),
        };
        if !is_valid_jsonrpc_response(&body) {
            return Vec::new();
        }

        let has_mcp_header = headers
            .get("MCP-Protocol-Version")
            .or_else(|| headers.get("mcp-protocol-version"))
            .is_some();
        let confidence = if has_mcp_header {
            Confidence::Confirmed
        } else {
            Confidence::High
        };

        let server_info = body
            .get("result")
            .and_then(|r| r.get("serverInfo"))
            .cloned()
            .unwrap_or(serde_json::json!(null));
        let capabilities = body
            .get("result")
            .and_then(|r| r.get("capabilities"))
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let mut signals = vec![Signal::new(
            DetectorType::McpDetector,
            "mcp_server_confirmed".to_string(),
            format!(
                "MCP server detected on {}:{}{} (confidence: {:?})",
                ip, port, path, confidence
            ),
            confidence,
            serde_json::json!({
                "ip": ip.to_string(),
                "port": port,
                "path": path,
                "server_info": server_info,
                "capabilities": capabilities,
                "mcp_header_present": has_mcp_header,
            }),
        )];

        signals.extend(Self::enumerate_capabilities_with(&client, &url, ip, port, path).await);
        signals
    }

    /// Try to enumerate MCP capabilities (tools, resources, prompts) on a confirmed endpoint.
    async fn enumerate_capabilities_with(
        client: &Client,
        url_base: &str,
        ip: IpAddr,
        port: u16,
        path: &str,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Try tools/list
        let tools_req = build_jsonrpc_request("tools/list", serde_json::json!({}));
        if let Some((body, _)) = Self::send_jsonrpc_with(client, url_base, &tools_req).await {
            if is_valid_jsonrpc_response(&body) {
                let tools = body
                    .get("result")
                    .and_then(|r| r.get("tools"))
                    .cloned()
                    .unwrap_or(serde_json::json!([]));
                signals.push(Signal::new(
                    DetectorType::McpDetector,
                    "mcp_tools_enumerated".to_string(),
                    format!(
                        "MCP tools enumerated on {}:{}{} ({} tools)",
                        ip,
                        port,
                        path,
                        tools.as_array().map_or(0, |a| a.len())
                    ),
                    Confidence::High,
                    serde_json::json!({
                        "ip": ip.to_string(),
                        "port": port,
                        "path": path,
                        "tools": tools,
                    }),
                ));
            }
        }

        // Try resources/list
        let resources_req = build_jsonrpc_request("resources/list", serde_json::json!({}));
        if let Some((body, _)) = Self::send_jsonrpc_with(client, url_base, &resources_req).await {
            if is_valid_jsonrpc_response(&body) {
                let resources = body
                    .get("result")
                    .and_then(|r| r.get("resources"))
                    .cloned()
                    .unwrap_or(serde_json::json!([]));
                signals.push(Signal::new(
                    DetectorType::McpDetector,
                    "mcp_resources_enumerated".to_string(),
                    format!(
                        "MCP resources enumerated on {}:{}{} ({} resources)",
                        ip,
                        port,
                        path,
                        resources.as_array().map_or(0, |a| a.len())
                    ),
                    Confidence::High,
                    serde_json::json!({
                        "ip": ip.to_string(),
                        "port": port,
                        "path": path,
                        "resources": resources,
                    }),
                ));
            }
        }

        // Try prompts/list
        let prompts_req = build_jsonrpc_request("prompts/list", serde_json::json!({}));
        if let Some((body, _)) = Self::send_jsonrpc_with(client, url_base, &prompts_req).await {
            if is_valid_jsonrpc_response(&body) {
                let prompts = body
                    .get("result")
                    .and_then(|r| r.get("prompts"))
                    .cloned()
                    .unwrap_or(serde_json::json!([]));
                signals.push(Signal::new(
                    DetectorType::McpDetector,
                    "mcp_prompts_enumerated".to_string(),
                    format!(
                        "MCP prompts enumerated on {}:{}{} ({} prompts)",
                        ip,
                        port,
                        path,
                        prompts.as_array().map_or(0, |a| a.len())
                    ),
                    Confidence::High,
                    serde_json::json!({
                        "ip": ip.to_string(),
                        "port": port,
                        "path": path,
                        "prompts": prompts,
                    }),
                ));
            }
        }

        signals
    }

    /// Cheap TCP connect check, identical to the endpoint_prober pre-filter.
    async fn is_port_open(ip: IpAddr, port: u16) -> bool {
        let addr = std::net::SocketAddr::new(ip, port);
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
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
        // Bound concurrent connect probes so we don't exhaust file descriptors
        // on a large /16 sweep. 256 is plenty to cover a /24 in seconds.
        let probe_sem = std::sync::Arc::new(Semaphore::new(256));

        // 1. Fan out a TCP-connect probe per (host, port) and collect open ones.
        let mut probe_handles: Vec<tokio::task::JoinHandle<(IpAddr, u16, bool)>> = Vec::new();
        for &ip in targets {
            for &port in MCP_PORTS {
                let permit = probe_sem.clone().acquire_owned().await?;
                probe_handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    (ip, port, Self::is_port_open(ip, port).await)
                }));
            }
        }
        let mut open_pairs: Vec<(IpAddr, u16)> = Vec::new();
        for h in probe_handles {
            if let Ok((ip, port, open)) = h.await {
                if open {
                    open_pairs.push((ip, port));
                }
            }
        }

        if open_pairs.is_empty() {
            return Ok(Vec::new());
        }

        // 2. For every open (host, port), probe every MCP path in parallel.
        let rpc_sem = std::sync::Arc::new(Semaphore::new(64));
        let client = self.client.clone();
        let mut probe_handles = Vec::new();
        for (ip, port) in open_pairs {
            for &path in MCP_PATHS {
                let permit = rpc_sem.clone().acquire_owned().await?;
                let client = client.clone();
                probe_handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    Self::probe_one(client, ip, port, path).await
                }));
            }
        }

        let mut signals = Vec::new();
        for h in probe_handles {
            if let Ok(mut sigs) = h.await {
                signals.append(&mut sigs);
            }
        }

        Ok(signals)
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
