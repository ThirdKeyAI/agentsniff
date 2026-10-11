use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::redirect;
use serde_json::Value;

use crate::config::ScanConfig;
use crate::http::read_json_limited;
use crate::models::{Confidence, DetectorType, Signal};

use super::Detector;

/// Ports to probe for AgentPin identity documents.
const AGENTPIN_PORTS: &[u16] = &[443, 8443, 8080, 3000, 8000];

/// Well-known path for AgentPin identity documents.
const AGENTPIN_PATH: &str = "/.well-known/agent-identity.json";

/// AgentPin discovery documents are small metadata objects. Leave generous
/// headroom while preventing concurrent probes from buffering arbitrary data.
const MAX_AGENTPIN_RESPONSE_BYTES: usize = 256 * 1024;

fn nonempty_string(object: &serde_json::Map<String, Value>, key: &str) -> bool {
    object
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn valid_public_key(key: &Value) -> bool {
    let Some(key) = key.as_object() else {
        return false;
    };
    nonempty_string(key, "kid")
        && key.get("kty").and_then(Value::as_str) == Some("EC")
        && key.get("crv").and_then(Value::as_str) == Some("P-256")
        && nonempty_string(key, "x")
        && nonempty_string(key, "y")
        && key.get("use").and_then(Value::as_str) == Some("sig")
}

/// Validate the required AgentPin v0.1 discovery-document shape.
///
/// This intentionally establishes only protocol discovery. Public-key
/// presence is not signature, delegation, revocation, or domain validation.
pub fn validate_agentpin_document(doc: &Value) -> bool {
    let Some(doc) = doc.as_object() else {
        return false;
    };
    if doc.get("agentpin_version").and_then(Value::as_str) != Some("0.1")
        || !nonempty_string(doc, "entity")
        || !matches!(
            doc.get("entity_type").and_then(Value::as_str),
            Some("maker" | "deployer" | "both")
        )
        || !nonempty_string(doc, "updated_at")
        || !doc
            .get("max_delegation_depth")
            .and_then(Value::as_u64)
            .is_some_and(|depth| depth <= 3)
    {
        return false;
    }

    let Some(public_keys) = doc.get("public_keys").and_then(Value::as_array) else {
        return false;
    };
    if public_keys.is_empty() || !public_keys.iter().all(valid_public_key) {
        return false;
    }

    let agents = match doc.get("agents") {
        Some(Value::Array(arr)) => arr,
        _ => return false,
    };

    for agent in agents {
        let Some(agent) = agent.as_object() else {
            return false;
        };
        if !nonempty_string(agent, "agent_id")
            || !nonempty_string(agent, "name")
            || !agent.get("capabilities").is_some_and(|capabilities| {
                capabilities
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string))
            })
            || !matches!(
                agent.get("status").and_then(Value::as_str),
                Some("active" | "suspended" | "deprecated")
            )
        {
            return false;
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

    /// Build a discovery signal from a structurally valid, unsigned AgentPin document.
    ///
    /// AgentSniff does not yet implement AgentPin's cryptographic verification
    /// profile. Document shape therefore proves protocol presence, not identity.
    fn signals_from_document(
        &self,
        ip: IpAddr,
        port: u16,
        scheme: &str,
        doc: &Value,
    ) -> Vec<Signal> {
        let entity = doc["entity"].as_str().unwrap_or("unknown");
        let agents = match doc.get("agents") {
            Some(Value::Array(arr)) => arr,
            _ => return Vec::new(),
        };
        let key_ids: Vec<&str> = doc
            .get("public_keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|key| key.get("kid").and_then(Value::as_str))
            .collect();
        let agent_ids: Vec<&str> = agents
            .iter()
            .filter_map(|agent| agent.get("agent_id").and_then(Value::as_str))
            .collect();

        vec![Signal::new(
            DetectorType::AgentpinProber,
            "agentpin_unsigned_document".to_string(),
            format!(
                "Unsigned AgentPin discovery document for entity '{}' found at {}://{}:{} ({} agent declaration(s))",
                entity,
                scheme,
                ip,
                port,
                agents.len()
            ),
            Confidence::Medium,
            serde_json::json!({
                "ip": ip.to_string(),
                "port": port,
                "scheme": scheme,
                "agentpin_version": doc.get("agentpin_version"),
                "entity": entity,
                "entity_type": doc.get("entity_type"),
                "key_ids": key_ids,
                "agent_ids": agent_ids,
                "agent_count": agents.len(),
                "a2a_endpoint": doc.get("a2a_endpoint"),
                "identity_verified": false,
                "entity_domain_verified": false,
                "credential_observed": false,
                "verification_status": "not_performed",
                "transport_compliant": scheme == "https",
            }),
        )]
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
        use tokio::sync::Semaphore;
        // Fan all probes out concurrently. Sequential probing turned this
        // into a multi-hour scan on a /24.
        let sem = std::sync::Arc::new(Semaphore::new(128));
        let client = self.client.clone();

        let mut handles: Vec<tokio::task::JoinHandle<(IpAddr, u16, &'static str, Option<Value>)>> =
            Vec::new();
        for &ip in targets {
            for &port in AGENTPIN_PORTS {
                let permit = sem.clone().acquire_owned().await?;
                let client = client.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    let url = format!("https://{}:{}{}", ip, port, AGENTPIN_PATH);
                    let resp = client.get(&url).send().await.ok();
                    let doc = match resp {
                        Some(r) if r.status().is_success() => {
                            read_json_limited::<Value>(r, MAX_AGENTPIN_RESPONSE_BYTES)
                                .await
                                .ok()
                        }
                        _ => None,
                    };
                    let doc = doc.filter(validate_agentpin_document);
                    (ip, port, "https", doc)
                }));
            }
            // HTTP on port 80
            let permit = sem.clone().acquire_owned().await?;
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let url = format!("http://{}:80{}", ip, AGENTPIN_PATH);
                let resp = client.get(&url).send().await.ok();
                let doc = match resp {
                    Some(r) if r.status().is_success() => {
                        read_json_limited::<Value>(r, MAX_AGENTPIN_RESPONSE_BYTES)
                            .await
                            .ok()
                    }
                    _ => None,
                };
                let doc = doc.filter(validate_agentpin_document);
                (ip, 80u16, "http", doc)
            }));
        }

        let mut signals = Vec::new();
        for h in handles {
            if let Ok((ip, port, scheme, Some(doc))) = h.await {
                signals.extend(self.signals_from_document(ip, port, scheme, &doc));
            }
        }
        Ok(signals)
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_document_never_claims_verified_identity() {
        let detector = AgentpinProber::new(&ScanConfig::default());
        let doc = serde_json::json!({
            "agentpin_version": "0.1",
            "entity": "attacker.example",
            "entity_type": "maker",
            "public_keys": [{
                "kid": "attacker-2026-01",
                "kty": "EC",
                "crv": "P-256",
                "x": "attacker-controlled-x",
                "y": "attacker-controlled-y",
                "use": "sig"
            }],
            "agents": [{
                "agent_id": "urn:agentpin:attacker.example:forged",
                "name": "Forged",
                "capabilities": ["admin:*"],
                "status": "active"
            }],
            "max_delegation_depth": 0,
            "updated_at": "2026-10-10T00:00:00Z"
        });

        let signals =
            detector.signals_from_document("192.0.2.10".parse().unwrap(), 443, "https", &doc);

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].confidence, Confidence::Medium);
        assert_eq!(signals[0].signal_type, "agentpin_unsigned_document");
        assert!(!signals[0].description.to_lowercase().contains("verified"));
        assert_eq!(signals[0].evidence["identity_verified"], false);
    }
}
