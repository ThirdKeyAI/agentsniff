use agentsniff::config::ScanConfig;
use agentsniff::detectors::agentpin_prober::*;
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;

#[test]
fn test_agentpin_prober_name() {
    let config = ScanConfig::default();
    let detector = AgentpinProber::new(&config);
    assert_eq!(detector.name(), "agentpin_prober");
    assert_eq!(detector.detector_type(), DetectorType::AgentpinProber);
}

#[test]
fn test_validate_valid_document() {
    let doc = serde_json::json!({
        "issuer": "example.com",
        "agents": [{
            "agent_id": "agent-1",
            "capabilities": ["chat", "code"]
        }]
    });
    assert!(validate_agentpin_document(&doc));
}

#[test]
fn test_validate_missing_issuer() {
    let doc = serde_json::json!({
        "agents": [{"agent_id": "a1", "capabilities": ["chat"]}]
    });
    assert!(!validate_agentpin_document(&doc));
}

#[test]
fn test_validate_missing_agent_fields() {
    let doc = serde_json::json!({
        "issuer": "example.com",
        "agents": [{"name": "incomplete"}]
    });
    assert!(!validate_agentpin_document(&doc));
}

#[test]
fn test_validate_empty_agents() {
    let doc = serde_json::json!({
        "issuer": "example.com",
        "agents": []
    });
    // Empty agents array is valid structurally
    assert!(validate_agentpin_document(&doc));
}

#[tokio::test]
async fn test_scan_unreachable_host() {
    let config = ScanConfig::default();
    let detector = AgentpinProber::new(&config);
    let targets = vec!["192.0.2.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
}
