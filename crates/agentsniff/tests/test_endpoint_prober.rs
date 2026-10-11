use agentsniff::config::ScanConfig;
use agentsniff::detectors::endpoint_prober::{
    match_mcp_client_name, match_request_user_agent, EndpointProberDetector,
};
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;

#[test]
fn test_endpoint_prober_name() {
    let config = ScanConfig::default();
    let detector = EndpointProberDetector::new(&config);
    assert_eq!(detector.name(), "endpoint_prober");
    assert_eq!(detector.detector_type(), DetectorType::EndpointProber);
}

#[test]
fn test_passive_framework_indicators_use_their_own_fields() {
    let signatures = serde_json::json!({
        "client": {
            "mcp_client_names": ["Example MCP"],
            "request_user_agents": ["example-agent/"]
        }
    });
    assert_eq!(
        match_mcp_client_name(&signatures, "example mcp"),
        vec!["client"]
    );
    assert_eq!(
        match_request_user_agent(&signatures, "example-agent/1.2"),
        vec!["client"]
    );
}

#[test]
fn test_probe_ports_defined() {
    use agentsniff::detectors::endpoint_prober::PROBE_PORTS;
    assert!(PROBE_PORTS.contains(&8080));
    assert!(PROBE_PORTS.contains(&3000));
    assert!(PROBE_PORTS.contains(&11434));
}

#[tokio::test]
async fn test_scan_unreachable_host() {
    let config = ScanConfig::default();
    let detector = EndpointProberDetector::new(&config);
    let targets = vec!["192.0.2.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
}
