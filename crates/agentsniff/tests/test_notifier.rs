use agentsniff::config::ScanConfig;
use agentsniff::models::{Confidence, DetectedAgent, DetectorType, ScanResult, Signal};
use agentsniff::notifier::Notifier;

fn make_config_disabled() -> ScanConfig {
    ScanConfig {
        alert_enabled: false,
        ..ScanConfig::default()
    }
}

fn make_config_enabled(min_agents: usize, min_confidence: f64) -> ScanConfig {
    ScanConfig {
        alert_enabled: true,
        alert_min_agents: min_agents,
        alert_min_confidence: min_confidence,
        alert_cooldown: 300,
        webhook_url: String::new(),
        smtp_host: String::new(),
        ..ScanConfig::default()
    }
}

#[test]
fn test_notifier_creates() {
    let config = ScanConfig::default();
    let notifier = Notifier::new(&config);
    // Simply verify construction succeeds (no panic).
    drop(notifier);
}

#[tokio::test]
async fn test_notifier_skips_when_disabled() {
    let config = make_config_disabled();
    let mut notifier = Notifier::new(&config);

    // Build a result with a high-confidence agent.
    let mut result = ScanResult::new();
    let mut agent = DetectedAgent::new("host1".into(), "10.0.0.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::PortScanner,
        "open_port".into(),
        "Port open".into(),
        Confidence::High,
        serde_json::json!({}),
    ));
    result.agents.push(agent);

    // Should return Ok(()) without attempting any network call.
    let res = notifier.check_and_notify(&result).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_notifier_skips_below_threshold() {
    // Require 2 agents but provide only 1.
    let config = make_config_enabled(2, 0.3);
    let mut notifier = Notifier::new(&config);

    let mut result = ScanResult::new();
    let mut agent = DetectedAgent::new("host1".into(), "10.0.0.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::EndpointProber,
        "framework_match".into(),
        "Ollama endpoint".into(),
        Confidence::High,
        serde_json::json!({}),
    ));
    result.agents.push(agent);

    // Only 1 qualifying agent; threshold is 2 – should skip silently.
    let res = notifier.check_and_notify(&result).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_notifier_skips_below_confidence() {
    // min_confidence = 0.9 but the agent only reaches ~0.8.
    let config = make_config_enabled(1, 0.9);
    let mut notifier = Notifier::new(&config);

    let mut result = ScanResult::new();
    let mut agent = DetectedAgent::new("host1".into(), "10.0.0.1".parse().unwrap());
    agent.add_signal(Signal::new(
        DetectorType::EndpointProber,
        "framework_match".into(),
        "Low-confidence hit".into(),
        Confidence::High, // weight 0.8 → score 0.8, below 0.9 threshold
        serde_json::json!({}),
    ));
    result.agents.push(agent);

    let res = notifier.check_and_notify(&result).await;
    assert!(res.is_ok());
}
