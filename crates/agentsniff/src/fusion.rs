use crate::models::*;

/// Corroborating detector types (everything except PortScanner).
pub const CORROBORATING_DETECTORS: &[DetectorType] = &[
    DetectorType::DnsMonitor,
    DetectorType::AgentpinProber,
    DetectorType::McpDetector,
    DetectorType::EndpointProber,
    DetectorType::TlsFingerprint,
    DetectorType::TrafficAnalyzer,
    DetectorType::SseDetector,
];

/// Apply cross-module corroboration rules.
///
/// Suppresses agents that only have LOW confidence port-scanner signals
/// unless corroborated by another detector or banner self-corroboration.
pub fn apply_fusion_rules(agents: Vec<DetectedAgent>) -> Vec<DetectedAgent> {
    agents
        .into_iter()
        .filter(|agent| {
            // Check if agent has ONLY low-confidence port-scanner signals
            let has_only_low_port_signals = agent.signals.iter().all(|s| {
                s.detector == DetectorType::PortScanner && s.confidence == Confidence::Low
            });

            if !has_only_low_port_signals {
                return true; // Keep -- has non-port or non-low signals
            }

            // Check for banner self-corroboration
            agent.signals.iter().any(|s| {
                if s.detector != DetectorType::PortScanner {
                    return false;
                }
                let banner = s
                    .evidence
                    .get("banner")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                !banner.is_empty()
                    && crate::detectors::port_scanner::classify_banner(banner).is_some()
            })
        })
        .collect()
}
