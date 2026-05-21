use agentsniff::config::ScanConfig;
use agentsniff::detectors::port_scanner::{classify_banner, classify_port, PortScannerDetector};
use agentsniff::detectors::Detector;
use agentsniff::models::{Confidence, DetectorType};

#[test]
fn test_port_scanner_name() {
    let config = ScanConfig::default();
    let detector = PortScannerDetector::new(&config);
    assert_eq!(detector.name(), "port_scanner");
    assert_eq!(detector.detector_type(), DetectorType::PortScanner);
}

#[test]
fn test_classify_agent_port() {
    assert_eq!(classify_port(11434), Some(("ollama", Confidence::Medium)));
    assert_eq!(classify_port(1234), Some(("lm_studio", Confidence::Medium)));
    assert_eq!(
        classify_port(6333),
        Some(("qdrant_http", Confidence::Medium))
    );
}

#[test]
fn test_classify_generic_port() {
    assert_eq!(
        classify_port(8080),
        Some(("generic_http", Confidence::Low))
    );
    assert_eq!(
        classify_port(3000),
        Some(("generic_http", Confidence::Low))
    );
}

#[test]
fn test_classify_unknown_port() {
    assert_eq!(classify_port(12345), None);
    assert_eq!(classify_port(22), None);
}

#[test]
fn test_classify_banner_match() {
    assert_eq!(classify_banner("Ollama/0.1.0"), Some("ollama"));
    assert_eq!(classify_banner("Qdrant v1.0"), Some("qdrant"));
}

#[test]
fn test_classify_banner_no_match() {
    assert_eq!(
        classify_banner("HTTP/1.1 200 OK\r\nServer: nginx"),
        None
    );
    assert_eq!(classify_banner("SSH-2.0-OpenSSH"), None);
}

#[tokio::test]
async fn test_scan_unreachable_host() {
    let config = ScanConfig::default();
    let detector = PortScannerDetector::new(&config);
    let targets = vec!["192.0.2.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
}

#[test]
fn test_custom_ports_included() {
    let mut config = ScanConfig::default();
    config.custom_agent_ports.insert(9999, "my_agent".into());
    let detector = PortScannerDetector::new(&config);
    // Default is 17 agent + 6 generic = 23, plus 1 custom = 24
    assert!(detector.port_count() > 20);
}
