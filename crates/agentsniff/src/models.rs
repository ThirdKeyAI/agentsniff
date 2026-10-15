use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Verified,
    Detected,
    Suspected,
    #[default]
    Unknown,
}

impl AgentStatus {
    /// Map a score into the legacy status field without making an identity
    /// claim. `Verified` is reserved for a trusted cryptographic identity.
    pub fn from_score(score: f64, _has_strong_signal: bool) -> Self {
        if score >= 0.5 {
            AgentStatus::Detected
        } else if score >= 0.2 {
            AgentStatus::Suspected
        } else {
            AgentStatus::Unknown
        }
    }
}

/// Confidence that an agent or agent-related service is present.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    #[default]
    Unknown,
    Suspected,
    Detected,
    Confirmed,
}

/// Assurance attached to the discovered agent identity, independent of
/// whether a protocol endpoint was successfully detected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAssurance {
    #[default]
    Unknown,
    SelfAsserted,
    SignedUntrusted,
    Invalid,
    TrustedVerified,
}

/// Security risk is intentionally separate from detection confidence.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    #[default]
    Unknown,
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// How an asset compares with the preceding persisted scan of the same scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetChangeStatus {
    #[default]
    Unclassified,
    New,
    Changed,
    Unchanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovedAsset {
    pub id: String,
    pub host: String,
    pub ip_address: IpAddr,
    pub port: Option<u16>,
    pub framework: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanDiff {
    pub baseline_scan_id: Option<String>,
    pub new_assets: Vec<String>,
    pub changed_assets: Vec<String>,
    pub unchanged_assets: Vec<String>,
    pub removed_assets: Vec<RemovedAsset>,
}

impl ScanDiff {
    pub fn actionable_count(&self) -> usize {
        self.new_assets.len() + self.changed_assets.len() + self.removed_assets.len()
    }
}

/// Signal type recording that enrichment found only non-agent services on a
/// host. It carries no detection weight; instead it scales the score by
/// `NON_AGENT_SERVICES_FACTOR`, so the reduction survives every recompute.
pub const NON_AGENT_SERVICES_SIGNAL: &str = "non_agent_services";

/// Score multiplier applied when a `non_agent_services` signal is present.
pub const NON_AGENT_SERVICES_FACTOR: f64 = 0.5;

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
    ServiceEnricher,
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
#[serde(default)]
pub struct DetectedAgent {
    pub id: String,
    pub host: String,
    pub ip_address: IpAddr,
    pub port: Option<u16>,
    pub transport: String,
    pub agent_type: Option<String>,
    pub framework: Option<String>,
    /// Backwards-compatible summary. `Verified` now means a trusted identity,
    /// not merely a high fused detection score.
    pub status: AgentStatus,
    pub presence_status: PresenceStatus,
    pub identity_assurance: IdentityAssurance,
    pub risk_level: RiskLevel,
    pub change_status: AssetChangeStatus,
    pub confidence_score: f64,
    pub confidence_level: String,
    pub signal_count: usize,
    pub signals: Vec<Signal>,
    pub agentpin_identity: Option<Value>,
    pub mcp_capabilities: Option<Value>,
    pub tls_fingerprint: Option<String>,
    pub metadata: Value,
    pub fingerprint: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl DetectedAgent {
    pub fn new(host: String, ip_address: IpAddr) -> Self {
        Self::for_endpoint(host, ip_address, None, "network")
    }

    /// Create a stable asset for one network service. Assets without a port
    /// represent passive, host-level observations.
    pub fn for_endpoint(
        host: String,
        ip_address: IpAddr,
        port: Option<u16>,
        transport: &str,
    ) -> Self {
        let now = Utc::now();
        let id = stable_asset_id(ip_address, port, transport);
        Self {
            id,
            host,
            ip_address,
            port,
            transport: transport.to_string(),
            agent_type: None,
            framework: None,
            status: AgentStatus::Unknown,
            presence_status: PresenceStatus::Unknown,
            identity_assurance: IdentityAssurance::Unknown,
            risk_level: RiskLevel::Unknown,
            change_status: AssetChangeStatus::Unclassified,
            confidence_score: 0.0,
            confidence_level: "low".to_string(),
            signal_count: 0,
            signals: Vec::new(),
            agentpin_identity: None,
            mcp_capabilities: None,
            tls_fingerprint: None,
            metadata: serde_json::json!({}),
            fingerprint: String::new(),
            first_seen: now,
            last_seen: now,
        }
    }

    /// Add a signal, promote its structured metadata into the agent summary,
    /// and update aggregate status.
    pub fn add_signal(&mut self, signal: Signal) {
        self.first_seen = self.first_seen.min(signal.timestamp);
        self.last_seen = self.last_seen.max(signal.timestamp);
        self.enrich_from_signal(&signal);
        self.signals.push(signal);
        self.update_status();
    }

    fn enrich_from_signal(&mut self, signal: &Signal) {
        let evidence = &signal.evidence;
        // Only a detector's local service port belongs to the asset key.
        // Passive `dst_port` values describe a remote peer and must not turn
        // a host-level observation into a misleading local service.
        let signal_port = evidence
            .get("port")
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
            DetectorType::PortScanner
            | DetectorType::NmapEnricher
            | DetectorType::ServiceEnricher => Some("agent_service"),
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
        let (penalties, evidence): (Vec<&Signal>, Vec<&Signal>) = self
            .signals
            .iter()
            .partition(|s| s.signal_type == NON_AGENT_SERVICES_SIGNAL);
        if evidence.is_empty() {
            return 0.0;
        }
        let score = 1.0
            - evidence
                .iter()
                .map(|s| 1.0 - s.confidence.weight())
                .product::<f64>();
        if penalties.is_empty() {
            score
        } else {
            score * NON_AGENT_SERVICES_FACTOR
        }
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
        self.presence_status = if self
            .signals
            .iter()
            .any(|signal| signal.confidence == Confidence::Confirmed)
        {
            PresenceStatus::Confirmed
        } else if score >= 0.5 {
            PresenceStatus::Detected
        } else if score >= 0.2 {
            PresenceStatus::Suspected
        } else {
            PresenceStatus::Unknown
        };
        self.identity_assurance = identity_assurance(&self.signals);
        self.risk_level = risk_level(&self.signals);
        self.status = if self.identity_assurance == IdentityAssurance::TrustedVerified {
            AgentStatus::Verified
        } else {
            match self.presence_status {
                PresenceStatus::Confirmed | PresenceStatus::Detected => AgentStatus::Detected,
                PresenceStatus::Suspected => AgentStatus::Suspected,
                PresenceStatus::Unknown => AgentStatus::Unknown,
            }
        };
        self.confidence_level = match self.presence_status {
            PresenceStatus::Confirmed => "confirmed",
            PresenceStatus::Detected => "high",
            PresenceStatus::Suspected => "medium",
            PresenceStatus::Unknown => "low",
        }
        .to_string();
        self.fingerprint = self.compute_fingerprint();
    }

    /// Hash material properties while excluding observation timestamps and
    /// other volatile counters. This drives scan-to-scan change detection.
    pub fn compute_fingerprint(&self) -> String {
        let mut signals: Vec<Value> = self
            .signals
            .iter()
            .map(|signal| {
                serde_json::json!({
                    "detector": signal.detector,
                    "signal_type": signal.signal_type,
                    "confidence": signal.confidence,
                    "evidence": stable_evidence(&signal.evidence),
                })
            })
            .collect();
        signals.sort_by_key(|value| serde_json::to_string(value).unwrap_or_default());
        let material = serde_json::json!({
            "ip_address": self.ip_address,
            "port": self.port,
            "transport": self.transport,
            "agent_type": self.agent_type,
            "framework": self.framework,
            "presence_status": self.presence_status,
            "identity_assurance": self.identity_assurance,
            "risk_level": self.risk_level,
            "agentpin_identity": self.agentpin_identity,
            "mcp_capabilities": self.mcp_capabilities,
            "tls_fingerprint": self.tls_fingerprint,
            "signals": signals,
        });
        digest_id("fp", &serde_json::to_vec(&material).unwrap_or_default())
    }
}

impl Default for DetectedAgent {
    fn default() -> Self {
        Self::new(String::new(), IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }
}

/// Deterministic identity for an observed host or service endpoint.
pub fn stable_asset_id(ip_address: IpAddr, port: Option<u16>, transport: &str) -> String {
    let key = match port {
        Some(port) => format!("{transport}://{ip_address}:{port}"),
        None => format!("host://{ip_address}"),
    };
    digest_id("asset", key.as_bytes())
}

fn digest_id(prefix: &str, material: &[u8]) -> String {
    let digest = Sha256::digest(material);
    let mut encoded = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("{prefix}-{encoded}")
}

fn identity_assurance(signals: &[Signal]) -> IdentityAssurance {
    let mut assurance = IdentityAssurance::Unknown;
    for signal in signals {
        let signature_status = signal
            .evidence
            .get("signature_status")
            .and_then(Value::as_str);
        let candidate = if signature_status == Some("trusted_verified")
            || (matches!(
                signal.detector,
                DetectorType::AgentpinProber | DetectorType::A2aDetector
            ) && signal
                .evidence
                .get("identity_verified")
                .and_then(Value::as_bool)
                == Some(true))
        {
            IdentityAssurance::TrustedVerified
        } else if signature_status == Some("invalid_trusted_signature")
            || signal.signal_type.contains("signature_invalid")
        {
            IdentityAssurance::Invalid
        } else if signature_status == Some("signed_untrusted") {
            IdentityAssurance::SignedUntrusted
        } else if matches!(
            signal.detector,
            DetectorType::AgentpinProber | DetectorType::A2aDetector
        ) && (signature_status == Some("unsigned")
            || signal.signal_type.contains("unsigned")
            || signal.signal_type.contains("discovered"))
        {
            IdentityAssurance::SelfAsserted
        } else {
            IdentityAssurance::Unknown
        };
        if identity_rank(candidate) > identity_rank(assurance) {
            assurance = candidate;
        }
    }
    assurance
}

fn identity_rank(value: IdentityAssurance) -> u8 {
    match value {
        IdentityAssurance::Unknown => 0,
        IdentityAssurance::SelfAsserted => 1,
        IdentityAssurance::SignedUntrusted => 2,
        IdentityAssurance::Invalid => 3,
        IdentityAssurance::TrustedVerified => 4,
    }
}

fn risk_level(signals: &[Signal]) -> RiskLevel {
    signals.iter().fold(RiskLevel::Unknown, |current, signal| {
        let explicit = signal
            .evidence
            .get("risk_level")
            .and_then(Value::as_str)
            .and_then(parse_risk_level);
        let inferred = if signal.signal_type.contains("signature_invalid")
            || signal
                .evidence
                .get("signature_status")
                .and_then(Value::as_str)
                == Some("invalid_trusted_signature")
        {
            Some(RiskLevel::High)
        } else {
            None
        };
        current.max(explicit.or(inferred).unwrap_or(RiskLevel::Unknown))
    })
}

fn parse_risk_level(value: &str) -> Option<RiskLevel> {
    match value.to_ascii_lowercase().as_str() {
        "informational" | "info" => Some(RiskLevel::Informational),
        "low" => Some(RiskLevel::Low),
        "medium" => Some(RiskLevel::Medium),
        "high" => Some(RiskLevel::High),
        "critical" => Some(RiskLevel::Critical),
        _ => None,
    }
}

fn stable_evidence(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| {
                    let key = key.to_ascii_lowercase();
                    !["timestamp", "observed_at", "duration", "latency", "elapsed"]
                        .iter()
                        .any(|volatile| key.contains(volatile))
                })
                .map(|(key, value)| (key.clone(), stable_evidence(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(stable_evidence).collect()),
        _ => value.clone(),
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
#[serde(default)]
pub struct ScanResult {
    pub scan_id: String,
    /// Deterministic identity for the resolved targets and enabled detector set.
    pub scope_id: String,
    pub target_network: String,
    pub agents: Vec<DetectedAgent>,
    pub detectors_run: Vec<DetectorType>,
    pub errors: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// True when the scan stopped early and must not become a baseline.
    pub cancelled: bool,
    pub diff: ScanDiff,
}

impl ScanResult {
    pub fn new() -> Self {
        Self {
            scan_id: Uuid::new_v4().to_string()[..8].to_string(),
            scope_id: String::new(),
            target_network: String::new(),
            agents: Vec::new(),
            detectors_run: Vec::new(),
            errors: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
            cancelled: false,
            diff: ScanDiff::default(),
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
