use std::net::IpAddr;

use async_trait::async_trait;

use crate::config::ScanConfig;
use crate::models::{DetectorType, Signal};

use super::Detector;

/// SSE/LLM streaming detector.
///
/// Currently a stub — passive packet analysis requires eBPF integration (Phase 8).
pub struct SseDetector;

impl SseDetector {
    /// Create a new SSE detector from scan configuration.
    pub fn new(_config: &ScanConfig) -> Self {
        Self
    }
}

#[async_trait]
impl Detector for SseDetector {
    fn name(&self) -> &str {
        "sse_detector"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::SseDetector
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, _targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        // No passive data without eBPF — return empty.
        Ok(Vec::new())
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// Packet timing analysis for SSE/LLM streaming pattern detection.
///
/// Will be fed by eBPF events in Phase 8.
pub struct PacketTimingAnalysis {
    pub packet_count: usize,
    pub median_size: f64,
    pub median_inter_arrival_ms: f64,
}

impl PacketTimingAnalysis {
    /// Analyze packet metadata for SSE/LLM streaming patterns.
    /// Returns confidence score if pattern matches, None otherwise.
    pub fn analyze(&self) -> Option<f64> {
        // Need minimum 10 packets
        if self.packet_count < 10 {
            return None;
        }
        // Median size < 500 bytes (small token chunks)
        if self.median_size >= 500.0 {
            return None;
        }
        // Median inter-arrival 10-200ms (token generation cadence)
        if self.median_inter_arrival_ms < 10.0 || self.median_inter_arrival_ms > 200.0 {
            return None;
        }
        // Confidence: 0.5 + (packet_count / 100), clamped to 0.95
        let confidence = (0.5 + self.packet_count as f64 / 100.0).min(0.95);
        Some(confidence)
    }
}
