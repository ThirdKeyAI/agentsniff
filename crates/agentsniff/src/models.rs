use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Confidence level for a detection signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

impl Confidence {
    /// Returns the numeric weight for Noisy-OR fusion.
    pub fn weight(self) -> f64 {
        match self {
            Confidence::Low => 0.2,
            Confidence::Medium => 0.5,
            Confidence::High => 0.8,
            Confidence::Confirmed => 1.0,
        }
    }
}

/// Overall status of a detected agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Verified,
    Detected,
    Suspected,
    Unknown,
}

impl AgentStatus {
    /// Determine status from a confidence score and whether a strong signal exists.
    pub fn from_score(score: f64, has_strong_signal: bool) -> Self {
        if score >= 0.9 && has_strong_signal {
            AgentStatus::Verified
        } else if score >= 0.5 {
            AgentStatus::Detected
        } else if score >= 0.2 {
            AgentStatus::Suspected
        } else {
            AgentStatus::Unknown
        }
    }
}

/// Types of detectors available in the scanning pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorType {
    DnsMonitor,
    PortScanner,
    AgentpinProber,
    A2aDetector,
    McpDetector,
    EndpointProber,
    TlsFingerprint,
    TrafficAnalyzer,
    SseDetector,
    NmapEnricher,
    Zeek,
}

/// A single detection signal emitted by a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub detector: DetectorType,
    pub signal_type: String,
    pub description: String,
    pub confidence: Confidence,
    pub evidence: Value,
    pub timestamp: DateTime<Utc>,
}

impl Signal {
    pub fn new(
        detector: DetectorType,
        signal_type: String,
        description: String,
        confidence: Confidence,
        evidence: Value,
    ) -> Self {
        Self {
            detector,
            signal_type,
            description,
            confidence,
            evidence,
            timestamp: Utc::now(),
        }
    }
}

/// A detected AI agent on the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedAgent {
    pub id: String,
    pub host: String,
    pub ip_address: IpAddr,
    pub port: Option<u16>,
    pub agent_type: Option<String>,
    pub framework: Option<String>,
    pub status: AgentStatus,
    pub confidence_score: f64,
    pub confidence_level: String,
    pub signal_count: usize,
    pub signals: Vec<Signal>,
    pub agentpin_identity: Option<Value>,
    pub mcp_capabilities: Option<Value>,
    pub tls_fingerprint: Option<String>,
    pub metadata: Value,
}

impl DetectedAgent {
    pub fn new(host: String, ip_address: IpAddr) -> Self {
        let id = Uuid::new_v4().to_string()[..8].to_string();
        Self {
            id,
            host,
            ip_address,
            port: None,
            agent_type: None,
            framework: None,
            status: AgentStatus::Unknown,
            confidence_score: 0.0,
            confidence_level: "low".to_string(),
            signal_count: 0,
            signals: Vec::new(),
            agentpin_identity: None,
            mcp_capabilities: None,
            tls_fingerprint: None,
            metadata: serde_json::json!({}),
        }
    }

    /// Add a signal, promote its structured metadata into the agent summary,
    /// and update aggregate status.
    pub fn add_signal(&mut self, signal: Signal) {
        self.enrich_from_signal(&signal);
        self.signals.push(signal);
        self.update_status();
    }

    fn enrich_from_signal(&mut self, signal: &Signal) {
        let evidence = &signal.evidence;
        let signal_port = evidence
            .get("port")
            .or_else(|| evidence.get("dst_port"))
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok());

        // Framework names produced by the endpoint detector come from the
        // signed catalog and are more specific than port-only candidates.
        if let Some(framework) = evidence
            .get("framework")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            self.framework = Some(framework.to_string());
            if let Some(port) = signal_port {
                self.port = Some(port);
            }
        } else if self.framework.is_none() {
            let framework = match signal.detector {
                DetectorType::McpDetector => Some("mcp"),
                DetectorType::AgentpinProber => Some("agentpin"),
                DetectorType::A2aDetector => Some("a2a"),
                DetectorType::PortScanner => evidence
                    .get("service_candidates")
                    .and_then(Value::as_array)
                    .filter(|candidates| candidates.len() == 1)
                    .and_then(|candidates| candidates.first())
                    .and_then(Value::as_str),
                _ => None,
            };
            if let Some(framework) = framework.filter(|value| !value.is_empty()) {
                self.framework = Some(framework.to_string());
            }
        }

        let inferred_type = match signal.detector {
            DetectorType::AgentpinProber => Some("agent_identity"),
            DetectorType::A2aDetector => Some("a2a_agent"),
            DetectorType::McpDetector => Some("mcp_server"),
            DetectorType::EndpointProber => Some("framework"),
            DetectorType::PortScanner | DetectorType::NmapEnricher => Some("agent_service"),
            DetectorType::DnsMonitor
            | DetectorType::TlsFingerprint
            | DetectorType::TrafficAnalyzer
            | DetectorType::Zeek => Some("ai_client"),
            DetectorType::SseDetector => Some("streaming_agent"),
        };
        if let Some(candidate) = inferred_type {
            let current_priority = self
                .agent_type
                .as_deref()
                .map(agent_type_priority)
                .unwrap_or(0);
            if agent_type_priority(candidate) > current_priority {
                self.agent_type = Some(candidate.to_string());
                if let Some(port) = signal_port {
                    self.port = Some(port);
                }
            }
        }

        if self.port.is_none() {
            self.port = signal_port;
        }

        match signal.detector {
            DetectorType::AgentpinProber => {
                self.agentpin_identity = Some(evidence.clone());
            }
            DetectorType::McpDetector if signal.signal_type == "mcp_server_confirmed" => {
                self.mcp_capabilities = Some(serde_json::json!({
                    "server_info": evidence.get("server_info"),
                    "capabilities": evidence.get("capabilities"),
                    "protocol_version": evidence.get("protocol_version"),
                }));
            }
            DetectorType::TlsFingerprint | DetectorType::Zeek => {
                self.tls_fingerprint = evidence
                    .get("ja3")
                    .or_else(|| evidence.get("ja3_string"))
                    .and_then(Value::as_str)
                    .map(String::from)
                    .or_else(|| {
                        evidence
                            .get("fingerprint_profile")
                            .and_then(|profile| profile.get("id"))
                            .and_then(Value::as_str)
                            .map(String::from)
                    });
            }
            _ => {}
        }
    }

    /// Compute aggregate confidence using Noisy-OR fusion:
    /// P = 1 - product(1 - weight_i)
    pub fn compute_confidence_score(&self) -> f64 {
        if self.signals.is_empty() {
            return 0.0;
        }
        1.0 - self
            .signals
            .iter()
            .map(|s| 1.0 - s.confidence.weight())
            .product::<f64>()
    }

    /// Returns true if any signal has High or Confirmed confidence.
    pub fn has_strong_signal(&self) -> bool {
        self.signals
            .iter()
            .any(|s| s.confidence >= Confidence::High)
    }

    /// Recalculate status and derived fields from current signals.
    pub fn update_status(&mut self) {
        let score = self.compute_confidence_score();
        self.confidence_score = score;
        self.signal_count = self.signals.len();
        self.status = AgentStatus::from_score(score, self.has_strong_signal());
        self.confidence_level = match self.status {
            AgentStatus::Verified => "confirmed",
            AgentStatus::Detected => "high",
            AgentStatus::Suspected => "medium",
            AgentStatus::Unknown => "low",
        }
        .to_string();
    }
}

fn agent_type_priority(agent_type: &str) -> u8 {
    match agent_type {
        "agent_identity" | "a2a_agent" => 6,
        "mcp_server" => 5,
        "framework" => 4,
        "agent_service" => 3,
        "streaming_agent" => 2,
        "ai_client" => 1,
        _ => 0,
    }
}

/// Result of a complete network scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub target_network: String,
    pub agents: Vec<DetectedAgent>,
    pub detectors_run: Vec<DetectorType>,
    pub errors: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            scan_id: Uuid::new_v4().to_string()[..8].to_string(),
            target_network: String::new(),
            agents: Vec::new(),
            detectors_run: Vec::new(),
            errors: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
        }
    }

    /// Duration in seconds, or None if scan is still running.
    pub fn duration_seconds(&self) -> Option<f64> {
        self.completed_at
            .map(|end| (end - self.started_at).num_milliseconds() as f64 / 1000.0)
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self::new()
    }
}
