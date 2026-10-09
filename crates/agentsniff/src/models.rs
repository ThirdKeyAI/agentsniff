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

    /// Add a signal and update the agent's status.
    pub fn add_signal(&mut self, signal: Signal) {
        self.signals.push(signal);
        self.update_status();
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
