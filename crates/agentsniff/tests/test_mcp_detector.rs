use agentsniff::config::ScanConfig;
use agentsniff::detectors::mcp_detector::*;
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;

#[test]
fn test_mcp_detector_name() {
    let config = ScanConfig::default();
    let detector = McpDetector::new(&config);
    assert_eq!(detector.name(), "mcp_detector");
    assert_eq!(detector.detector_type(), DetectorType::McpDetector);
}

#[test]
fn test_build_jsonrpc_request() {
    let req = build_jsonrpc_request(
        "initialize",
        serde_json::json!({"protocolVersion": "2024-11-05"}),
    );
    assert_eq!(req["jsonrpc"], "2.0");
    assert_eq!(req["method"], "initialize");
    assert!(req["id"].is_number());
}

#[test]
fn test_valid_jsonrpc_response() {
    let valid = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}});
    assert!(is_valid_jsonrpc_response(&valid));

    let error =
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "fail"}});
    assert!(!is_valid_jsonrpc_response(&error));

    let invalid = serde_json::json!({"status": "ok"});
    assert!(!is_valid_jsonrpc_response(&invalid));
}

#[tokio::test]
async fn test_scan_unreachable_host() {
    let mut config = ScanConfig::default();
    config.http_timeout = 1.0; // Short timeout for test speed
    let detector = McpDetector::new(&config);
    let targets = vec!["192.0.2.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
}
