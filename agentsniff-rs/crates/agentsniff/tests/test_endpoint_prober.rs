use agentsniff::config::ScanConfig;
use agentsniff::detectors::endpoint_prober::EndpointProberDetector;
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;

#[test]
fn test_endpoint_prober_name() {
    let config = ScanConfig::default();
    let detector = EndpointProberDetector::new(&config);
    assert_eq!(detector.name(), "endpoint_prober");
    assert_eq!(detector.detector_type(), DetectorType::EndpointProber);
}

#[test]
fn test_probe_ports_defined() {
    use agentsniff::detectors::endpoint_prober::PROBE_PORTS;
    assert!(PROBE_PORTS.contains(&8080));
    assert!(PROBE_PORTS.contains(&3000));
    assert!(PROBE_PORTS.contains(&11434));
}

#[tokio::test]
async fn test_scan_unreachable_host() {
    let config = ScanConfig::default();
    let detector = EndpointProberDetector::new(&config);
    let targets = vec!["192.0.2.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
}
