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
        "agentpin_version": "0.1",
        "entity": "example.com",
        "entity_type": "maker",
        "public_keys": [{
            "kid": "example-2026-01",
            "kty": "EC",
            "crv": "P-256",
            "x": "base64url-x",
            "y": "base64url-y",
            "use": "sig"
        }],
        "agents": [{
            "agent_id": "urn:agentpin:example.com:agent-1",
            "name": "Agent One",
            "capabilities": ["read:chat", "execute:code"],
            "status": "active"
        }],
        "max_delegation_depth": 1,
        "updated_at": "2026-10-10T00:00:00Z"
    });
    assert!(validate_agentpin_document(&doc));
}

#[test]
fn test_validate_obsolete_minimal_shape_is_rejected() {
    let doc = serde_json::json!({
        "issuer": "example.com",
        "agents": [{"agent_id": "a1", "capabilities": ["chat"]}]
    });
    assert!(!validate_agentpin_document(&doc));
}

#[test]
fn test_validate_missing_agent_fields() {
    let doc = serde_json::json!({
        "agentpin_version": "0.1",
        "entity": "example.com",
        "entity_type": "maker",
        "public_keys": [{
            "kid": "example-2026-01",
            "kty": "EC",
            "crv": "P-256",
            "x": "x",
            "y": "y",
            "use": "sig"
        }],
        "agents": [{"name": "incomplete"}]
        ,"max_delegation_depth": 0,
        "updated_at": "2026-10-10T00:00:00Z"
    });
    assert!(!validate_agentpin_document(&doc));
}

#[test]
fn test_validate_empty_agents() {
    let doc = serde_json::json!({
        "agentpin_version": "0.1",
        "entity": "example.com",
        "entity_type": "maker",
        "public_keys": [{
            "kid": "example-2026-01",
            "kty": "EC",
            "crv": "P-256",
            "x": "x",
            "y": "y",
            "use": "sig"
        }],
        "agents": [],
        "max_delegation_depth": 0,
        "updated_at": "2026-10-10T00:00:00Z"
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
