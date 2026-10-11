use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use reqwest::Client;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::ScanConfig;
use crate::http::read_json_limited;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::{canonicalize_json, load_verifying_key_from_pem};

use super::Detector;

const A2A_PATH: &str = "/.well-known/agent-card.json";
const LEGACY_A2A_PATH: &str = "/.well-known/agent.json";
const A2A_PORTS: &[u16] = &[80, 443, 3000, 3001, 5000, 8000, 8001, 8080, 8501];
const MAX_AGENT_CARD_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentCardSignatureStatus {
    Unsigned,
    TrustedVerified { kid: String },
    PresentButUntrusted,
    InvalidTrustedSignature { kid: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCardValidation {
    pub signature_status: AgentCardSignatureStatus,
}

fn nonempty_string(doc: &serde_json::Map<String, Value>, key: &str) -> bool {
    doc.get(key)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

/// Validate the required Agent Card shape and verify any ES256 signature whose
/// `kid` has an out-of-band trusted public key. A key embedded in the document
/// or its JWS header is deliberately never treated as a trust anchor.
pub fn validate_agent_card(
    card: &Value,
    trusted_keys: &HashMap<String, String>,
) -> Option<AgentCardValidation> {
    let doc = card.as_object()?;
    if !nonempty_string(doc, "name")
        || !nonempty_string(doc, "description")
        || !nonempty_string(doc, "version")
        || !doc.get("capabilities").is_some_and(Value::is_object)
        || !doc.get("defaultInputModes").is_some_and(Value::is_array)
        || !doc.get("defaultOutputModes").is_some_and(Value::is_array)
        || !doc.get("skills").is_some_and(Value::is_array)
    {
        return None;
    }

    let has_interface = doc
        .get("supportedInterfaces")
        .and_then(Value::as_array)
        .is_some_and(|interfaces| !interfaces.is_empty())
        || doc
            .get("url")
            .and_then(Value::as_str)
            .is_some_and(|url| !url.is_empty());
    if !has_interface {
        return None;
    }

    let Some(signatures) = doc.get("signatures").and_then(Value::as_array) else {
        return Some(AgentCardValidation {
            signature_status: AgentCardSignatureStatus::Unsigned,
        });
    };
    if signatures.is_empty() {
        return Some(AgentCardValidation {
            signature_status: AgentCardSignatureStatus::Unsigned,
        });
    }

    let mut payload = card.clone();
    if let Some(payload_doc) = payload.as_object_mut() {
        payload_doc.remove("signatures");
    }
    let canonical = canonicalize_json(&payload);
    let encoded_payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical.as_bytes());
    let mut saw_trusted = None;

    for signature_doc in signatures.iter().filter_map(Value::as_object) {
        let Some(protected) = signature_doc.get("protected").and_then(Value::as_str) else {
            continue;
        };
        let Some(signature_b64) = signature_doc.get("signature").and_then(Value::as_str) else {
            continue;
        };
        let Some(protected_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protected)
            .ok()
        else {
            continue;
        };
        let Some(header) = serde_json::from_slice::<Value>(&protected_bytes).ok() else {
            continue;
        };
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            continue;
        }
        let Some(kid) = header.get("kid").and_then(Value::as_str) else {
            continue;
        };
        let Some(pem) = trusted_keys.get(kid) else {
            continue;
        };
        saw_trusted = Some(kid.to_string());
        let Some(key) = load_verifying_key_from_pem(pem) else {
            continue;
        };
        let Some(signature_bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .ok()
        else {
            continue;
        };
        let Ok(signature) = Signature::from_slice(&signature_bytes) else {
            continue;
        };
        let signing_input = format!("{}.{}", protected, encoded_payload);
        if key.verify(signing_input.as_bytes(), &signature).is_ok() {
            return Some(AgentCardValidation {
                signature_status: AgentCardSignatureStatus::TrustedVerified {
                    kid: kid.to_string(),
                },
            });
        }
    }

    Some(AgentCardValidation {
        signature_status: match saw_trusted {
            Some(kid) => AgentCardSignatureStatus::InvalidTrustedSignature { kid },
            None => AgentCardSignatureStatus::PresentButUntrusted,
        },
    })
}

pub struct A2aDetector {
    timeout: Duration,
    concurrency: usize,
    client: Client,
    trusted_keys: HashMap<String, String>,
}

impl A2aDetector {
    pub fn new(config: &ScanConfig) -> Self {
        let timeout = Duration::from_secs_f64(config.http_timeout);
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build reqwest client");
        Self {
            timeout,
            concurrency: config.http_concurrency,
            client,
            trusted_keys: config.a2a_trusted_keys.clone(),
        }
    }

    async fn is_port_open(ip: IpAddr, port: u16, timeout: Duration) -> bool {
        tokio::time::timeout(
            timeout.min(Duration::from_millis(500)),
            TcpStream::connect((ip, port)),
        )
        .await
        .is_ok_and(|result| result.is_ok())
    }

    async fn probe_path(
        client: &Client,
        trusted_keys: &HashMap<String, String>,
        ip: IpAddr,
        port: u16,
        path: &str,
    ) -> Option<Signal> {
        let scheme = if port == 443 { "https" } else { "http" };
        let host = if ip.is_ipv6() {
            format!("[{}]", ip)
        } else {
            ip.to_string()
        };
        let url = format!("{}://{}:{}{}", scheme, host, port, path);
        let response = client.get(&url).send().await.ok()?;
        if response.status() != reqwest::StatusCode::OK {
            return None;
        }
        let card = read_json_limited::<Value>(response, MAX_AGENT_CARD_BYTES)
            .await
            .ok()?;
        let validation = validate_agent_card(&card, trusted_keys)?;

        let (signal_type, description, confidence, signature_status, kid) =
            match validation.signature_status {
                AgentCardSignatureStatus::Unsigned => (
                    "a2a_agent_card_discovered",
                    "A2A Agent Card discovered (self-asserted, unsigned)",
                    Confidence::High,
                    "unsigned",
                    None,
                ),
                AgentCardSignatureStatus::PresentButUntrusted => (
                    "a2a_agent_card_signed_untrusted",
                    "A2A Agent Card discovered with no locally trusted signer",
                    Confidence::High,
                    "signed_untrusted",
                    None,
                ),
                AgentCardSignatureStatus::TrustedVerified { kid } => (
                    "a2a_agent_card_identity_verified",
                    "A2A Agent Card identity cryptographically verified",
                    Confidence::Confirmed,
                    "trusted_verified",
                    Some(kid),
                ),
                AgentCardSignatureStatus::InvalidTrustedSignature { kid } => (
                    "a2a_agent_card_signature_invalid",
                    "A2A Agent Card has an invalid signature for a trusted key",
                    Confidence::Medium,
                    "invalid_trusted_signature",
                    Some(kid),
                ),
            };

        Some(Signal::new(
            DetectorType::A2aDetector,
            signal_type.to_string(),
            format!("{} at {}", description, url),
            confidence,
            serde_json::json!({
                "ip": ip.to_string(),
                "port": port,
                "path": path,
                "name": card.get("name"),
                "version": card.get("version"),
                "signature_status": signature_status,
                "trusted_kid": kid,
                "legacy_discovery_path": path == LEGACY_A2A_PATH,
            }),
        ))
    }
}

#[async_trait]
impl Detector for A2aDetector {
    fn name(&self) -> &str {
        "a2a_detector"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::A2aDetector
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        let semaphore = std::sync::Arc::new(Semaphore::new(self.concurrency.max(1)));
        let mut connect_handles = Vec::new();
        for &ip in targets {
            for &port in A2A_PORTS {
                let permit = semaphore.clone().acquire_owned().await?;
                let timeout = self.timeout;
                connect_handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    (ip, port, Self::is_port_open(ip, port, timeout).await)
                }));
            }
        }

        let mut open_pairs = Vec::new();
        for handle in connect_handles {
            if let Ok((ip, port, true)) = handle.await {
                open_pairs.push((ip, port));
            }
        }

        let mut handles = Vec::new();
        for (ip, port) in open_pairs {
            for path in [A2A_PATH, LEGACY_A2A_PATH] {
                let permit = semaphore.clone().acquire_owned().await?;
                let client = self.client.clone();
                let trusted_keys = self.trusted_keys.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    Self::probe_path(&client, &trusted_keys, ip, port, path).await
                }));
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
