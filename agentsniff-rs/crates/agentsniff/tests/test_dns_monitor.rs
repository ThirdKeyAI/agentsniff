use agentsniff::config::ScanConfig;
use agentsniff::detectors::dns_monitor::{matches_known_domain, DnsMonitorDetector};
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;

// ---------------------------------------------------------------------------
// matches_known_domain tests
// ---------------------------------------------------------------------------

#[test]
fn test_matches_llm_domain() {
    let llm_domains = vec!["api.openai.com".to_string(), "api.anthropic.com".to_string()];
    let infra_domains = vec!["langsmith.com".to_string()];
    let suffixes: Vec<String> = vec![];

    assert_eq!(
        matches_known_domain("api.openai.com", &llm_domains, &infra_domains, &suffixes),
        Some("llm_api")
    );
    assert_eq!(
        matches_known_domain("api.anthropic.com", &llm_domains, &infra_domains, &suffixes),
        Some("llm_api")
    );
}

#[test]
fn test_matches_llm_domain_case_insensitive() {
    let llm_domains = vec!["api.openai.com".to_string()];
    let infra_domains: Vec<String> = vec![];
    let suffixes: Vec<String> = vec![];

    assert_eq!(
        matches_known_domain("API.OPENAI.COM", &llm_domains, &infra_domains, &suffixes),
        Some("llm_api")
    );
}

#[test]
fn test_matches_infra_domain() {
    let llm_domains: Vec<String> = vec![];
    let infra_domains = vec!["langsmith.com".to_string(), "wandb.ai".to_string()];
    let suffixes: Vec<String> = vec![];

    assert_eq!(
        matches_known_domain("langsmith.com", &llm_domains, &infra_domains, &suffixes),
        Some("agent_infrastructure")
    );
    assert_eq!(
        matches_known_domain("wandb.ai", &llm_domains, &infra_domains, &suffixes),
        Some("agent_infrastructure")
    );
}

#[test]
fn test_matches_domain_suffix() {
    let llm_domains: Vec<String> = vec![];
    let infra_domains: Vec<String> = vec![];
    // Suffix without leading dot
    let suffixes = vec!["openai.com".to_string()];

    // A subdomain that is not an exact match but shares the suffix
    assert_eq!(
        matches_known_domain(
            "models.openai.com",
            &llm_domains,
            &infra_domains,
            &suffixes
        ),
        Some("domain_suffix")
    );
}

#[test]
fn test_matches_domain_suffix_with_leading_dot() {
    let llm_domains: Vec<String> = vec![];
    let infra_domains: Vec<String> = vec![];
    // Suffix with leading dot
    let suffixes = vec![".anthropic.com".to_string()];

    assert_eq!(
        matches_known_domain(
            "bedrock.anthropic.com",
            &llm_domains,
            &infra_domains,
            &suffixes
        ),
        Some("domain_suffix")
    );
}

#[test]
fn test_no_match() {
    let llm_domains = vec!["api.openai.com".to_string()];
    let infra_domains = vec!["langsmith.com".to_string()];
    let suffixes = vec!["openai.com".to_string()];

    assert_eq!(
        matches_known_domain("example.com", &llm_domains, &infra_domains, &suffixes),
        None
    );
    assert_eq!(
        matches_known_domain("google.com", &llm_domains, &infra_domains, &suffixes),
        None
    );
    assert_eq!(
        matches_known_domain("notreally-openai.com", &llm_domains, &infra_domains, &suffixes),
        None
    );
}

#[test]
fn test_empty_lists_no_match() {
    let llm_domains: Vec<String> = vec![];
    let infra_domains: Vec<String> = vec![];
    let suffixes: Vec<String> = vec![];

    assert_eq!(
        matches_known_domain("api.openai.com", &llm_domains, &infra_domains, &suffixes),
        None
    );
}

// ---------------------------------------------------------------------------
// DnsMonitorDetector structural tests
// ---------------------------------------------------------------------------

#[test]
fn test_dns_monitor_name_and_type() {
    let config = ScanConfig::default();
    let detector = DnsMonitorDetector::new(&config, None);
    assert_eq!(detector.name(), "dns_monitor");
    assert_eq!(detector.detector_type(), DetectorType::DnsMonitor);
}

#[tokio::test]
async fn test_dns_monitor_scan_no_targets() {
    let config = ScanConfig::default();
    let detector = DnsMonitorDetector::new(&config, None);
    let targets: Vec<std::net::IpAddr> = vec![];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(
        signals.is_empty(),
        "Expected no signals for empty target list, got {}",
        signals.len()
    );
}

#[tokio::test]
async fn test_dns_monitor_setup_teardown() {
    let config = ScanConfig::default();
    let mut detector = DnsMonitorDetector::new(&config, None);
    assert!(detector.setup().await.is_ok());
    assert!(detector.teardown().await.is_ok());
}
