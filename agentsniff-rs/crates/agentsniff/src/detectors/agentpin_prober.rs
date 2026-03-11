use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::redirect;
use serde_json::Value;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};

use super::Detector;

/// Ports to probe for AgentPin identity documents.
const AGENTPIN_PORTS: &[u16] = &[443, 8443, 8080, 3000, 8000];

/// Well-known path for AgentPin identity documents.
const AGENTPIN_PATH: &str = "/.well-known/agent-identity.json";

/// Validates that an AgentPin document has the required structure.
///
/// Required top-level fields: "issuer" (string), "agents" (array).
/// Each agent must have "agent_id" (string) and "capabilities" (array).
pub fn validate_agentpin_document(doc: &Value) -> bool {
    // Check issuer is a string
    let issuer = match doc.get("issuer") {
        Some(v) if v.is_string() => true,
        _ => return false,
    };
    if !issuer {
        return false;
    }

    // Check agents is an array
    let agents = match doc.get("agents") {
        Some(Value::Array(arr)) => arr,
        _ => return false,
    };

    // Validate each agent entry
    for agent in agents {
        match agent.get("agent_id") {
            Some(v) if v.is_string() => {}
            _ => return false,
        }
        match agent.get("capabilities") {
            Some(Value::Array(_)) => {}
            _ => return false,
        }
    }

    true
}

/// AgentPin prober that discovers AI agent identities via the AgentPin protocol.
pub struct AgentpinProber {
    #[allow(dead_code)]
    timeout: Duration,
    client: reqwest::Client,
}

impl AgentpinProber {
    /// Create a new AgentPin prober from scan configuration.
    pub fn new(config: &ScanConfig) -> Self {
        let timeout = Duration::from_secs_f64(config.http_timeout);
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build reqwest client");

        Self { timeout, client }
    }

    /// Attempt to fetch and validate an AgentPin document from a URL.
    async fn probe_url(&self, url: &str) -> Option<Value> {
        let resp = self.client.get(url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let doc: Value = resp.json().await.ok()?;
        if validate_agentpin_document(&doc) {
            Some(doc)
        } else {
            None
        }
    }

    /// Build signals from a validated AgentPin document.
    fn signals_from_document(&self, ip: IpAddr, port: u16, scheme: &str, doc: &Value) -> Vec<Signal> {
        let mut signals = Vec::new();

        let issuer = doc["issuer"].as_str().unwrap_or("unknown");
        let agents = match doc.get("agents") {
            Some(Value::Array(arr)) => arr,
            _ => return signals,
        };

        for agent in agents {
            let agent_id = agent["agent_id"].as_str().unwrap_or("unknown");
            let capabilities = &agent["capabilities"];
            let protocol_version = agent.get("protocol_version");

            let description = format!(
                "AgentPin identity verified for agent '{}' from issuer '{}' at {}://{}:{}",
                agent_id, issuer, scheme, ip, port
            );

            let mut evidence = serde_json::json!({
                "ip": ip.to_string(),
                "port": port,
                "scheme": scheme,
                "issuer": issuer,
                "agent_id": agent_id,
                "capabilities": capabilities,
            });

            if let Some(pv) = protocol_version {
                evidence["protocol_version"] = pv.clone();
            }

            signals.push(Signal::new(
                DetectorType::AgentpinProber,
                "agentpin_verified_agent".to_string(),
                description,
                Confidence::Confirmed,
                evidence,
            ));
        }

        signals
    }
}

#[async_trait]
impl Detector for AgentpinProber {
    fn name(&self) -> &str {
        "agentpin_prober"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::AgentpinProber
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        let mut signals = Vec::new();

        for &ip in targets {
            // Try HTTPS on each AgentPin port
            for &port in AGENTPIN_PORTS {
                let url = format!("https://{}:{}{}", ip, port, AGENTPIN_PATH);
                if let Some(doc) = self.probe_url(&url).await {
                    signals.extend(self.signals_from_document(ip, port, "https", &doc));
                }
            }

            // Try HTTP on port 80
            let url = format!("http://{}:{}{}", ip, 80, AGENTPIN_PATH);
            if let Some(doc) = self.probe_url(&url).await {
                signals.extend(self.signals_from_document(ip, 80, "http", &doc));
            }
        }

        Ok(signals)
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
