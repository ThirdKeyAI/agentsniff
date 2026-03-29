use agentsniff::models::*;

#[test]
fn test_confidence_weight() {
    assert_eq!(Confidence::Low.weight(), 0.2);
    assert_eq!(Confidence::Medium.weight(), 0.5);
    assert_eq!(Confidence::High.weight(), 0.8);
    assert_eq!(Confidence::Confirmed.weight(), 1.0);
}

#[test]
fn test_confidence_ordering() {
    assert!(Confidence::Confirmed > Confidence::High);
    assert!(Confidence::High > Confidence::Medium);
    assert!(Confidence::Medium > Confidence::Low);
}

#[test]
fn test_noisy_or_single_signal() {
    let agent = DetectedAgent::new("test-host".into(), "192.168.1.1".parse().unwrap());
    assert_eq!(agent.confidence_score, 0.0);
}

#[test]
fn test_noisy_or_multiple_signals() {
    let mut agent = DetectedAgent::new("test-host".into(), "192.168.1.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_port".into(),
        "Port 11434 open".into(),
        Confidence::Medium,
        serde_json::json!({"port": 11434}),
    ));
    agent.add_signal(Signal::new(
        DetectorType::EndpointProber,
        "framework_match".into(),
        "Ollama endpoint".into(),
        Confidence::High,
        serde_json::json!({"framework": "ollama"}),
    ));
    let score = agent.confidence_score;
    assert!((score - 0.9).abs() < 1e-10);
}

#[test]
fn test_agent_status_from_score() {
    assert_eq!(AgentStatus::from_score(0.95, true), AgentStatus::Verified);
    assert_eq!(AgentStatus::from_score(0.95, false), AgentStatus::Detected);
    assert_eq!(AgentStatus::from_score(0.6, false), AgentStatus::Detected);
    assert_eq!(AgentStatus::from_score(0.3, false), AgentStatus::Suspected);
    assert_eq!(AgentStatus::from_score(0.1, false), AgentStatus::Unknown);
}

#[test]
fn test_signal_serialization() {
    let signal = Signal::new(
        DetectorType::DnsMonitor,
        "llm_api_domain".into(),
        "DNS query to api.openai.com".into(),
        Confidence::High,
        serde_json::json!({"domain": "api.openai.com"}),
    );
    let json = serde_json::to_string(&signal).unwrap();
    let deserialized: Signal = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.detector, DetectorType::DnsMonitor);
    assert_eq!(deserialized.confidence, Confidence::High);
}

#[test]
fn test_detector_type_serialization() {
    let dt = DetectorType::NmapEnricher;
    let json = serde_json::to_string(&dt).unwrap();
    assert_eq!(json, "\"nmap_enricher\"");
    let deserialized: DetectorType = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, DetectorType::NmapEnricher);

    let dt = DetectorType::Zeek;
    let json = serde_json::to_string(&dt).unwrap();
    assert_eq!(json, "\"zeek\"");
    let deserialized: DetectorType = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, DetectorType::Zeek);
}

#[test]
fn test_detected_agent_serialization() {
    let agent = DetectedAgent::new("test-host".into(), "192.168.1.1".parse().unwrap());
    let json = serde_json::to_string(&agent).unwrap();
    let deserialized: DetectedAgent = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.host, "test-host");
    assert_eq!(deserialized.ip_address.to_string(), "192.168.1.1");
}
