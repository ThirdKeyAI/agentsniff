use agentsniff::fusion::apply_fusion_rules;
use agentsniff::models::*;

#[test]
fn test_low_port_signal_suppressed_without_corroboration() {
    let mut agent = DetectedAgent::new("host".into(), "192.168.1.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_agent_port".into(),
        "Port 8080 open".into(),
        Confidence::Low,
        serde_json::json!({"port": 8080, "banner": ""}),
    ));
    let filtered = apply_fusion_rules(vec![agent]);
    assert!(filtered.is_empty());
}

#[test]
fn test_low_port_signal_kept_with_corroboration() {
    let mut agent = DetectedAgent::new("host".into(), "192.168.1.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_agent_port".into(),
        "Port 8080 open".into(),
        Confidence::Low,
        serde_json::json!({"port": 8080, "banner": ""}),
    ));
    agent.add_signal(Signal::new(
        DetectorType::EndpointProber,
        "framework_match".into(),
        "LangChain endpoint".into(),
        Confidence::High,
        serde_json::json!({}),
    ));
    let filtered = apply_fusion_rules(vec![agent]);
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_medium_port_signal_not_suppressed() {
    let mut agent = DetectedAgent::new("host".into(), "192.168.1.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "agent_service_identified".into(),
        "Ollama on 11434".into(),
        Confidence::Medium,
        serde_json::json!({"port": 11434, "service": "ollama"}),
    ));
    let filtered = apply_fusion_rules(vec![agent]);
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_banner_self_corroboration() {
    let mut agent = DetectedAgent::new("host".into(), "192.168.1.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_agent_port".into(),
        "Port 3000 open".into(),
        Confidence::Low,
        serde_json::json!({"port": 3000, "banner": "Ollama/0.1"}),
    ));
    let filtered = apply_fusion_rules(vec![agent]);
    assert_eq!(filtered.len(), 1); // Kept because banner matches known pattern
}

#[test]
fn test_no_signals_agent_suppressed() {
    let agent = DetectedAgent::new("host".into(), "192.168.1.1".parse().unwrap());
    let filtered = apply_fusion_rules(vec![agent]);
    // No signals at all -- all() returns true for empty iterator, so it gets suppressed
    // Actually, all() on empty returns true, so has_only_low_port_signals=true,
    // then banner check fails -> suppressed
    assert!(filtered.is_empty());
}

#[test]
fn test_multiple_agents_mixed() {
    let mut agent1 = DetectedAgent::new("host1".into(), "192.168.1.1".parse().unwrap());
    agent1.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_agent_port".into(),
        "Port 8080".into(),
        Confidence::Low,
        serde_json::json!({"port": 8080, "banner": ""}),
    ));

    let mut agent2 = DetectedAgent::new("host2".into(), "192.168.1.2".parse().unwrap());
    agent2.add_signal(Signal::new(
        DetectorType::McpDetector,
        "mcp_server_confirmed".into(),
        "MCP on 3000".into(),
        Confidence::Confirmed,
        serde_json::json!({}),
    ));

    let filtered = apply_fusion_rules(vec![agent1, agent2]);
    assert_eq!(filtered.len(), 1); // Only agent2 kept
    assert_eq!(filtered[0].host, "host2");
}
