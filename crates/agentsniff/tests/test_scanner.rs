use agentsniff::config::ScanConfig;
use agentsniff::scanner::resolve_targets;

#[test]
fn test_resolve_cidr_24() {
    let config = ScanConfig {
        target_network: "192.168.1.0/24".into(),
        target_hosts: vec![],
        exclude_hosts: vec![],
        ..ScanConfig::default()
    };
    let targets = resolve_targets(&config).unwrap();
    assert_eq!(targets.len(), 254); // .1 through .254
    assert!(targets.contains(&"192.168.1.1".parse().unwrap()));
    assert!(targets.contains(&"192.168.1.254".parse().unwrap()));
    assert!(!targets.contains(&"192.168.1.0".parse().unwrap())); // network
    assert!(!targets.contains(&"192.168.1.255".parse().unwrap())); // broadcast
}

#[test]
fn test_resolve_cidr_32() {
    let config = ScanConfig {
        target_network: "10.0.0.5/32".into(),
        ..ScanConfig::default()
    };
    let targets = resolve_targets(&config).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0], "10.0.0.5".parse::<std::net::IpAddr>().unwrap());
}

#[test]
fn test_rejects_oversized_cidr_before_expansion() {
    let config = ScanConfig {
        target_network: "10.0.0.0/8".into(),
        ..ScanConfig::default()
    };
    let err = resolve_targets(&config).unwrap_err();
    assert!(err.to_string().contains("maximum is 65536"));
}

#[test]
fn test_resolve_with_exclusions() {
    let config = ScanConfig {
        target_network: "192.168.1.0/30".into(), // .1, .2
        exclude_hosts: vec!["192.168.1.1".into()],
        ..ScanConfig::default()
    };
    let targets = resolve_targets(&config).unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0],
        "192.168.1.2".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn test_resolve_with_additional_hosts() {
    let config = ScanConfig {
        target_network: "192.168.1.0/32".into(),
        target_hosts: vec!["10.0.0.1".into()],
        ..ScanConfig::default()
    };
    let targets = resolve_targets(&config).unwrap();
    assert_eq!(targets.len(), 2);
}

#[test]
fn test_resolve_dedup() {
    let config = ScanConfig {
        target_network: "192.168.1.1/32".into(),
        target_hosts: vec!["192.168.1.1".into()], // duplicate
        ..ScanConfig::default()
    };
    let targets = resolve_targets(&config).unwrap();
    assert_eq!(targets.len(), 1);
}

#[tokio::test]
async fn test_run_scan_empty_targets() {
    use agentsniff::scanner::run_scan;
    let config = ScanConfig {
        target_network: "192.0.2.0/32".into(), // single unreachable
        enable_dns_monitor: false,
        enable_tls_fingerprint: false,
        enable_traffic_analyzer: false,
        // Use very short timeouts so the test completes quickly
        port_scan_timeout: 0.1,
        http_timeout: 0.1,
        ..ScanConfig::default()
    };
    // Only port scanner + endpoint prober + mcp detector + agentpin + sse
    let result = run_scan(&config, None, None, None).await.unwrap();
    assert!(result.agents.is_empty()); // unreachable host
    assert!(result.completed_at.is_some());
}
