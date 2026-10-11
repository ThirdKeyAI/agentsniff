use agentsniff::baseline::{apply_scan_diff, BaselineTracker};
use agentsniff::models::{
    AssetChangeStatus, Confidence, DetectedAgent, DetectorType, ScanResult, Signal,
};

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
    second.agents.push(make_agent_with_signal(
        "host2",
        "10.0.0.2",
        "framework_match",
    ));
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
    first.agents.push(make_agent_with_signal(
        "host2",
        "10.0.0.2",
        "framework_match",
    ));
    tracker.process(&first);

    // Second scan contains only the already-known pairs.
    let mut second = ScanResult::new();
    second
        .agents
        .push(make_agent_with_signal("host1", "10.0.0.1", "open_port"));
    second.agents.push(make_agent_with_signal(
        "host2",
        "10.0.0.2",
        "framework_match",
    ));
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

#[test]
fn test_persisted_scan_diff_classifies_new_changed_unchanged_and_removed() {
    let mut previous = ScanResult::new();
    previous.scan_id = "baseline".into();
    previous.target_network = "10.0.0.0/24".into();
    previous
        .agents
        .push(make_agent_with_signal("unchanged", "10.0.0.1", "open_port"));
    previous
        .agents
        .push(make_agent_with_signal("changed", "10.0.0.2", "open_port"));
    previous
        .agents
        .push(make_agent_with_signal("removed", "10.0.0.3", "open_port"));
    apply_scan_diff(&mut previous, None);

    let prior_first_seen = previous.agents[0].first_seen;
    let mut current = ScanResult::new();
    current.target_network = previous.target_network.clone();
    current
        .agents
        .push(make_agent_with_signal("unchanged", "10.0.0.1", "open_port"));
    let mut changed = make_agent_with_signal("changed", "10.0.0.2", "open_port");
    changed.add_signal(Signal::new(
        DetectorType::McpDetector,
        "mcp_server_confirmed".into(),
        "MCP server".into(),
        Confidence::Confirmed,
        serde_json::json!({}),
    ));
    current.agents.push(changed);
    current
        .agents
        .push(make_agent_with_signal("new", "10.0.0.4", "framework_match"));

    apply_scan_diff(&mut current, Some(&previous));

    assert_eq!(current.diff.baseline_scan_id.as_deref(), Some("baseline"));
    assert_eq!(current.diff.new_assets.len(), 1);
    assert_eq!(current.diff.changed_assets.len(), 1);
    assert_eq!(current.diff.unchanged_assets.len(), 1);
    assert_eq!(current.diff.removed_assets.len(), 1);
    assert_eq!(
        current.agents[0].change_status,
        AssetChangeStatus::Unchanged
    );
    assert_eq!(current.agents[0].first_seen, prior_first_seen);
    assert_eq!(current.agents[1].change_status, AssetChangeStatus::Changed);
    assert_eq!(current.agents[2].change_status, AssetChangeStatus::New);
    assert_eq!(
        current.diff.removed_assets[0].ip_address.to_string(),
        "10.0.0.3"
    );
}

#[test]
fn test_cancelled_scan_never_produces_a_diff() {
    let mut current = ScanResult::new();
    current.cancelled = true;
    current
        .agents
        .push(make_agent_with_signal("partial", "10.0.0.9", "open_port"));

    apply_scan_diff(&mut current, None);

    assert_eq!(
        current.agents[0].change_status,
        AssetChangeStatus::Unclassified
    );
    assert_eq!(current.diff.actionable_count(), 0);
}

#[test]
fn test_degraded_scan_never_produces_actionable_changes() {
    let mut previous = ScanResult::new();
    previous.scan_id = "baseline".into();
    previous
        .agents
        .push(make_agent_with_signal("known", "10.0.0.1", "open_port"));
    apply_scan_diff(&mut previous, None);

    let mut current = ScanResult::new();
    current.errors.push("MCP detector failed".into());
    apply_scan_diff(&mut current, Some(&previous));

    assert_eq!(current.diff.baseline_scan_id.as_deref(), Some("baseline"));
    assert_eq!(current.diff.actionable_count(), 0);
}
