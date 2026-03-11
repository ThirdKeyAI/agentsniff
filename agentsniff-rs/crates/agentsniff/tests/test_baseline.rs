use agentsniff::baseline::BaselineTracker;
use agentsniff::models::{Confidence, DetectedAgent, DetectorType, ScanResult, Signal};

fn make_agent_with_signal(host: &str, ip: &str, signal_type: &str) -> DetectedAgent {
    let mut agent = DetectedAgent::new(host.into(), ip.parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        signal_type.into(),
        format!("Signal {signal_type} on {host}"),
        Confidence::Medium,
        serde_json::json!({}),
    ));
    agent
}

#[test]
fn test_baseline_first_scan_no_anomalies() {
    let mut tracker = BaselineTracker::new();
    assert!(!tracker.is_initialized());

    let mut result = ScanResult::new();
    result
        .agents
        .push(make_agent_with_signal("host1", "10.0.0.1", "open_port"));

    let anomalies = tracker.process(&result);

    // First scan establishes the baseline; no anomalies reported.
    assert!(anomalies.is_empty());
    assert!(tracker.is_initialized());
    assert_eq!(tracker.known_pair_count(), 1);
}

#[test]
fn test_baseline_second_scan_detects_new() {
    let mut tracker = BaselineTracker::new();

    // First scan: establish baseline with one pair.
    let mut first = ScanResult::new();
    first
        .agents
        .push(make_agent_with_signal("host1", "10.0.0.1", "open_port"));
    tracker.process(&first);

    // Second scan: same pair plus a brand-new pair.
    let mut second = ScanResult::new();
    second
        .agents
        .push(make_agent_with_signal("host1", "10.0.0.1", "open_port"));
    second
        .agents
        .push(make_agent_with_signal("host2", "10.0.0.2", "framework_match"));
    let anomalies = tracker.process(&second);

    assert_eq!(anomalies.len(), 1);
    assert_eq!(anomalies[0].host, "host2");
    assert_eq!(anomalies[0].signal_type, "framework_match");
}

#[test]
fn test_baseline_known_pairs_not_flagged() {
    let mut tracker = BaselineTracker::new();

    // Establish baseline with two pairs.
    let mut first = ScanResult::new();
    first
        .agents
        .push(make_agent_with_signal("host1", "10.0.0.1", "open_port"));
    first
        .agents
        .push(make_agent_with_signal("host2", "10.0.0.2", "framework_match"));
    tracker.process(&first);

    // Second scan contains only the already-known pairs.
    let mut second = ScanResult::new();
    second
        .agents
        .push(make_agent_with_signal("host1", "10.0.0.1", "open_port"));
    second
        .agents
        .push(make_agent_with_signal("host2", "10.0.0.2", "framework_match"));
    let anomalies = tracker.process(&second);

    assert!(anomalies.is_empty());
}

#[test]
fn test_baseline_empty_scan() {
    let mut tracker = BaselineTracker::new();

    // Establish baseline with an empty scan.
    let anomalies_first = tracker.process(&ScanResult::new());
    assert!(anomalies_first.is_empty());
    assert!(tracker.is_initialized());
    assert_eq!(tracker.known_pair_count(), 0);

    // Second empty scan: nothing new.
    let anomalies_second = tracker.process(&ScanResult::new());
    assert!(anomalies_second.is_empty());
}

#[test]
fn test_baseline_multiple_signals_per_agent() {
    let mut tracker = BaselineTracker::new();

    // First scan: one agent with two signals.
    let mut agent = DetectedAgent::new("host1".into(), "10.0.0.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_port".into(),
        "Port open".into(),
        Confidence::Medium,
        serde_json::json!({}),
    ));
    agent.add_signal(Signal::new(
        DetectorType::EndpointProber,
        "framework_match".into(),
        "Framework detected".into(),
        Confidence::High,
        serde_json::json!({}),
    ));
    let mut first = ScanResult::new();
    first.agents.push(agent);
    tracker.process(&first);

    assert_eq!(tracker.known_pair_count(), 2);

    // Second scan: same agent with same signals + one new signal.
    let mut agent2 = DetectedAgent::new("host1".into(), "10.0.0.1".parse().unwrap());
    agent2.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_port".into(),
        "Port open".into(),
        Confidence::Medium,
        serde_json::json!({}),
    ));
    agent2.add_signal(Signal::new(
        DetectorType::EndpointProber,
        "framework_match".into(),
        "Framework detected".into(),
        Confidence::High,
        serde_json::json!({}),
    ));
    agent2.add_signal(Signal::new(
        DetectorType::DnsMonitor,
        "llm_api_domain".into(),
        "New DNS signal".into(),
        Confidence::Low,
        serde_json::json!({}),
    ));
    let mut second = ScanResult::new();
    second.agents.push(agent2);
    let anomalies = tracker.process(&second);

    assert_eq!(anomalies.len(), 1);
    assert_eq!(anomalies[0].signal_type, "llm_api_domain");
}
