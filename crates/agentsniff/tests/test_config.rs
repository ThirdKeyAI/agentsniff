use agentsniff::config::{default_config_yaml, ScanConfig};
use std::collections::HashMap;

#[test]
fn test_default_config() {
    let config = ScanConfig::default();
    assert_eq!(config.target_network, "192.168.1.0/24");
    assert!(config.enable_dns_monitor);
    assert!(config.enable_port_scanner);
    assert_eq!(config.api_port, 9090);
    assert_eq!(config.port_scan_timeout, 2.0);
    assert_eq!(config.port_scan_concurrency, 100);
    assert!(config.alert_changes_only);
    assert!(config.agentpin_trust_bundle_path.is_empty());
    assert_eq!(
        config.agentpin_pin_store_path,
        "~/.agentsniff/agentpin-pins.json"
    );
    assert!(config.agentpin_expected_audience.is_empty());
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
    let config = ScanConfig::from_yaml_file(&write_temp_yaml("basic", yaml)).unwrap();
    assert_eq!(config.target_network, "10.0.0.0/16");
    assert!(!config.enable_dns_monitor);
    assert_eq!(config.api_port, 8080);
    assert_eq!(config.port_scan_timeout, 5.0);
    assert_eq!(config.custom_llm_domains, vec!["my-llm.example.com"]);
}

#[test]
fn test_config_serialization_roundtrip() {
    let config = ScanConfig::default();
    let yaml = serde_saphyr::to_string(&config).unwrap();
    let deserialized = ScanConfig::from_yaml_file(&write_temp_yaml("roundtrip", &yaml)).unwrap();
    assert_eq!(config.target_network, deserialized.target_network);
    assert_eq!(config.api_port, deserialized.api_port);
}

#[test]
fn test_storage_config_defaults() {
    let config = ScanConfig::default();
    assert_eq!(config.storage.backend, "sqlite");
    assert_eq!(config.storage.redis_channel, "agentsniff:events:v1");
}

#[test]
fn test_config_env_override() {
    std::env::set_var("AGENTSNIFF_TARGET_NETWORK", "172.16.0.0/12");
    let config = ScanConfig::from_env_with_defaults(ScanConfig::default()).unwrap();
    assert_eq!(config.target_network, "172.16.0.0/12");
    std::env::remove_var("AGENTSNIFF_TARGET_NETWORK");
}

#[test]
fn test_config_zeek_defaults() {
    let config = ScanConfig::default();
    assert!(!config.zeek_enabled);
    assert!(config.zeek_log_path.is_empty());
    assert_eq!(config.zeek_time_window, 300);
}

#[test]
fn test_config_enrich_defaults() {
    let config = ScanConfig::default();
    assert!(!config.enrich_enabled);
    assert_eq!(config.enrich_timeout, 300);
    assert!(config.nmap_xml_import.is_empty());
}

#[test]
fn test_config_zeek_from_yaml() {
    let yaml = r#"
zeek_enabled: true
zeek_log_path: "/opt/zeek/logs/current"
zeek_time_window: 600
"#;
    let config = ScanConfig::from_yaml_file(&write_temp_yaml("zeek", yaml)).unwrap();
    assert!(config.zeek_enabled);
    assert_eq!(config.zeek_log_path, "/opt/zeek/logs/current");
    assert_eq!(config.zeek_time_window, 600);
}

fn write_temp_yaml(name: &str, yaml: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "agentsniff-config-{}-{name}.yaml",
        std::process::id()
    ));
    std::fs::write(&path, yaml).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn test_config_enrich_from_yaml() {
    let path = write_temp_yaml(
        "enrich",
        "enrich_enabled: true\nenrich_timeout: 60\nnmap_xml_import: \"scan.xml\"\n",
    );
    let config = ScanConfig::from_yaml_file(&path).unwrap();
    assert!(config.enrich_enabled);
    assert_eq!(config.enrich_timeout, 60);
    assert_eq!(config.nmap_xml_import, "scan.xml");
}

#[test]
fn test_config_rejects_removed_nmap_enabled_true() {
    let path = write_temp_yaml("nmap-on", "nmap_enabled: true\n");
    let err = ScanConfig::from_yaml_file(&path).unwrap_err().to_string();
    assert!(err.contains("enrich_enabled"), "{err}");
    assert!(err.contains("--nmap-xml"), "{err}");
}

#[test]
fn test_config_ignores_disabled_nmap_keys() {
    let path = write_temp_yaml(
        "nmap-off",
        "nmap_enabled: false\nnmap_scan_args: \"-sV\"\nnmap_timeout: 120\n",
    );
    let config = ScanConfig::from_yaml_file(&path).unwrap();
    assert!(!config.enrich_enabled);
}

#[test]
fn test_default_config_yaml_contains_sections() {
    let yaml = default_config_yaml();
    assert!(yaml.contains("target_network"));
    assert!(yaml.contains("enable_dns_monitor"));
    assert!(yaml.contains("zeek_enabled"));
    assert!(yaml.contains("enrich_enabled"));
    assert!(!yaml.contains("nmap_enabled"));
    assert!(yaml.contains("ebpf_interface"));
    assert!(yaml.contains("alert_enabled"));
    assert!(yaml.contains("alert_changes_only"));
    assert!(yaml.contains("agentpin_trust_bundle_path"));
    assert!(yaml.contains("agentpin_expected_audience"));
}

#[test]
fn test_webhook_destination_change_clears_retained_headers() {
    let mut config = ScanConfig {
        webhook_url: "https://old.example/hook".into(),
        webhook_headers: HashMap::from([("Authorization".into(), "Bearer secret".into())]),
        ..ScanConfig::default()
    };

    assert!(!config.set_webhook_destination("https://old.example/hook".into()));
    assert_eq!(config.webhook_headers.len(), 1);

    assert!(config.set_webhook_destination("https://new.example/hook".into()));
    assert!(config.webhook_headers.is_empty());
    assert_eq!(config.webhook_url, "https://new.example/hook");
}

#[test]
fn test_probe_port_overrides_detector_port_lists() {
    let mut config = ScanConfig::default();
    assert_eq!(config.ports_or(&[80, 443]), vec![80, 443]);
    config.probe_port = Some(8765);
    assert_eq!(config.ports_or(&[80, 443]), vec![8765]);
    // Runtime-only: never read from or written to YAML.
    assert!(!serde_saphyr::to_string(&config)
        .unwrap()
        .contains("probe_port"));
}

#[test]
fn yaml_preserves_ports_aliases_pem_and_defaults() {
    let config = ScanConfig::from_yaml_file(&write_temp_yaml(
        "yaml-types",
        r#"
target_hosts: &hosts ["127.0.0.1"]
exclude_hosts: *hosts
custom_agent_ports:
  8443: custom-agent
agentpin_trust_bundle_path: bundle.json
storage:
  backend: postgres
webhook_headers:
  X-Certificate: |
    -----BEGIN PUBLIC KEY-----
    example
    -----END PUBLIC KEY-----
custom_framework_signatures:
  example:
    ports: [8443]
    enabled: true
probe_port: 9999
"#,
    ))
    .unwrap();
    assert_eq!(
        config.custom_agent_ports.get(&8443).unwrap(),
        "custom-agent"
    );
    assert_eq!(config.target_hosts, config.exclude_hosts);
    assert_eq!(config.storage.backend, "postgres");
    assert_eq!(config.storage.redis_channel, "agentsniff:events:v1");
    assert!(config.webhook_headers["X-Certificate"].ends_with("-----END PUBLIC KEY-----\n"));
    assert!(config.probe_port.is_none());
    assert_eq!(
        config.custom_framework_signatures["example"]["ports"][0],
        8443
    );
    assert_eq!(
        config.custom_framework_signatures["example"]["enabled"],
        true
    );
}

#[test]
fn yaml_rejects_ambiguous_or_malformed_config_without_secret_snippets() {
    for (index, invalid) in [
        "api_port: 1\napi_port: 2\n",
        "enable_dns_monitor: yes\n",
        "enable_dns_monitor: on\n",
        "enable_dns_monitor: \"false\"\n",
        "api_port: \"8123\"\n",
        "api_token: 12345\n",
        "target_network: true\n",
        "api_port: [\n",
        "api_port: 9090\n---\napi_port: 8080\n",
    ]
    .iter()
    .enumerate()
    {
        let input = format!("smtp_password: nearby-secret-marker\n{invalid}");
        let error = ScanConfig::from_yaml_file(&write_temp_yaml(&format!("bad-{index}"), &input))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("nearby-secret-marker"), "{error}");
    }
}

#[test]
fn yaml_does_not_activate_merge_keys() {
    let config =
        ScanConfig::from_yaml_file(&write_temp_yaml("merge", "<<: {api_port: 8123}\n")).unwrap();
    assert_eq!(config.api_port, ScanConfig::default().api_port);
}

#[test]
fn yaml_preserves_boolean_case_and_redacts_invalid_secret_values() {
    for spelling in ["true", "True", "TRUE"] {
        let path = write_temp_yaml(
            &format!("nmap-{spelling}"),
            &format!("nmap_enabled: {spelling}\n"),
        );
        assert!(ScanConfig::from_yaml_file(&path)
            .unwrap_err()
            .to_string()
            .contains("enrich_enabled"));
    }
    for (index, yaml) in [
        "smtp_password: 12345678901234567890\n",
        "api_token: [secret-scalar-marker]\n",
    ]
    .iter()
    .enumerate()
    {
        let error = ScanConfig::from_yaml_file(&write_temp_yaml(&format!("secret-{index}"), yaml))
            .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(!rendered.contains("12345678901234567890"));
        assert!(!rendered.contains("secret-scalar-marker"));
    }
}
