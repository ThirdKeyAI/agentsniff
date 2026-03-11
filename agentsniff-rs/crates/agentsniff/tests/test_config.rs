use agentsniff::config::ScanConfig;

#[test]
fn test_default_config() {
    let config = ScanConfig::default();
    assert_eq!(config.target_network, "192.168.1.0/24");
    assert!(config.enable_dns_monitor);
    assert!(config.enable_port_scanner);
    assert_eq!(config.api_port, 9090);
    assert_eq!(config.port_scan_timeout, 2.0);
    assert_eq!(config.port_scan_concurrency, 100);
}

#[test]
fn test_config_from_yaml() {
    let yaml = r#"
target_network: "10.0.0.0/16"
enable_dns_monitor: false
api_port: 8080
port_scan_timeout: 5.0
custom_llm_domains:
  - "my-llm.example.com"
"#;
    let config: ScanConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.target_network, "10.0.0.0/16");
    assert!(!config.enable_dns_monitor);
    assert_eq!(config.api_port, 8080);
    assert_eq!(config.port_scan_timeout, 5.0);
    assert_eq!(config.custom_llm_domains, vec!["my-llm.example.com"]);
}

#[test]
fn test_config_serialization_roundtrip() {
    let config = ScanConfig::default();
    let yaml = serde_yaml::to_string(&config).unwrap();
    let deserialized: ScanConfig = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(config.target_network, deserialized.target_network);
    assert_eq!(config.api_port, deserialized.api_port);
}

#[test]
fn test_storage_config_defaults() {
    let config = ScanConfig::default();
    assert_eq!(config.storage.backend, "sqlite");
}

#[test]
fn test_config_env_override() {
    std::env::set_var("AGENTSNIFF_TARGET_NETWORK", "172.16.0.0/12");
    let config = ScanConfig::from_env_with_defaults(ScanConfig::default());
    assert_eq!(config.target_network, "172.16.0.0/12");
    std::env::remove_var("AGENTSNIFF_TARGET_NETWORK");
}
