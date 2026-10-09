use agentsniff::config::default_config_yaml;

#[test]
fn test_default_config_yaml_is_valid() {
    let yaml = default_config_yaml();
    let uncommented: String = yaml
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let config: agentsniff::config::ScanConfig = serde_yaml::from_str(&uncommented).unwrap();
    assert_eq!(config.target_network, "192.168.1.0/24");
    assert!(config.enable_dns_monitor);
}
