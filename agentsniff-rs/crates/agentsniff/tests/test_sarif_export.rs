use agentsniff::models::{Confidence, DetectedAgent, DetectorType, ScanResult, Signal};
use agentsniff::sarif_export::to_sarif;

#[test]
fn test_sarif_schema_version() {
    let result = ScanResult::new();
    let sarif = to_sarif(&result);
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["$schema"]
        .as_str()
        .unwrap()
        .contains("sarif"));
}

#[test]
fn test_sarif_empty_scan() {
    let result = ScanResult::new();
    let sarif = to_sarif(&result);
    assert!(sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn test_sarif_with_agents() {
    let mut result = ScanResult::new();

    let mut agent = DetectedAgent::new("agent-host".into(), "10.1.2.3".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_port".into(),
        "Port 11434 open".into(),
        Confidence::High,
        serde_json::json!({"port": 11434}),
    ));
    agent.add_signal(Signal::new(
        DetectorType::EndpointProber,
        "framework_match".into(),
        "Ollama endpoint detected".into(),
        Confidence::Confirmed,
        serde_json::json!({"framework": "ollama"}),
    ));
    result.agents.push(agent);

    let sarif = to_sarif(&result);

    // Should have 2 results (one per signal).
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);

    // Should have 2 deduplicated rules.
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn test_sarif_deduplicates_rules() {
    let mut result = ScanResult::new();

    // Two agents each emitting the same signal_type.
    for ip in ["10.0.0.1", "10.0.0.2"] {
        let mut agent = DetectedAgent::new(ip.into(), ip.parse().unwrap());
        agent.add_signal(Signal::new(
            DetectorType::DnsMonitor,
            "llm_api_domain".into(),
            "DNS query to LLM API".into(),
            Confidence::Medium,
            serde_json::json!({}),
        ));
        result.agents.push(agent);
    }

    let sarif = to_sarif(&result);

    // 2 results but only 1 rule (deduped by signal_type).
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1);
}

#[test]
fn test_sarif_confidence_levels() {
    let mut result = ScanResult::new();

    let confidences = [
        (Confidence::Confirmed, "error"),
        (Confidence::High, "error"),
        (Confidence::Medium, "warning"),
        (Confidence::Low, "note"),
    ];

    for (i, (conf, _expected_level)) in confidences.iter().enumerate() {
        let mut agent =
            DetectedAgent::new(format!("host{i}"), format!("10.0.0.{i}").parse().unwrap());
        agent.add_signal(Signal::new(
            DetectorType::PortScanner,
            format!("signal_{i}"),
            format!("Signal at level {conf:?}"),
            *conf,
            serde_json::json!({}),
        ));
        result.agents.push(agent);
    }

    let sarif = to_sarif(&result);
    let results = sarif["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), confidences.len());

    for (i, (_conf, expected_level)) in confidences.iter().enumerate() {
        assert_eq!(results[i]["level"].as_str().unwrap(), *expected_level);
    }
}
