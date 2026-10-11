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
    assert_eq!(detector.supported_protocols().first(), Some(&"2026-07-28"));
}

#[test]
fn test_parse_sse_jsonrpc_response() {
    let body = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
    let parsed = parse_json_or_sse(body).unwrap();
    assert!(is_valid_jsonrpc_response(&parsed));
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

#[test]
fn test_agentpin_capability_is_discovery_not_identity_verification() {
    let result = serde_json::json!({
        "capabilities": {
            "agentpin": {"version": "0.1", "required": false}
        }
    });
    let capability = agentpin_capability(&result, "capabilities.agentpin").unwrap();
    assert_eq!(capability["version"], "0.1");
    assert_eq!(capability["required"], false);
    assert!(agentpin_capability(&result, "capabilities.missing").is_none());
}

#[tokio::test]
async fn test_scan_unreachable_host() {
    let config = ScanConfig {
        http_timeout: 1.0, // Short timeout for test speed
        ..ScanConfig::default()
    };
    let detector = McpDetector::new(&config);
    let targets = vec!["192.0.2.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
}
