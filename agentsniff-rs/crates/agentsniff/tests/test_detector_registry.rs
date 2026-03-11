use std::net::IpAddr;

use agentsniff::config::ScanConfig;
use agentsniff::detectors::{Detector, DetectorRegistry};
use agentsniff::models::{Confidence, DetectorType, Signal};
use async_trait::async_trait;

struct MockDetector;

#[async_trait]
impl Detector for MockDetector {
    fn name(&self) -> &str {
        "mock"
    }
    fn detector_type(&self) -> DetectorType {
        DetectorType::PortScanner
    }
    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn scan(&self, _targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        Ok(vec![Signal::new(
            DetectorType::PortScanner,
            "test".into(),
            "test signal".into(),
            Confidence::Low,
            serde_json::json!({}),
        )])
    }
    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn test_detector_scan_returns_signals() {
    let detector = MockDetector;
    let targets: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].signal_type, "test");
}

#[test]
fn test_detector_registry_create_enabled() {
    let config = ScanConfig::default();
    let registry = DetectorRegistry::new();
    let detectors = registry.create_enabled(&config);
    assert!(detectors.is_empty());
}

#[test]
fn test_detector_registry_with_registered_factory() {
    let mut registry = DetectorRegistry::new();
    registry.register("mock", "enable_port_scanner", |_config| {
        Box::new(MockDetector)
    });

    let config = ScanConfig::default(); // port_scanner enabled by default
    let detectors = registry.create_enabled(&config);
    assert_eq!(detectors.len(), 1);
    assert_eq!(detectors[0].name(), "mock");
}

#[test]
fn test_detector_registry_respects_disabled() {
    let mut registry = DetectorRegistry::new();
    registry.register("mock", "enable_port_scanner", |_config| {
        Box::new(MockDetector)
    });

    let mut config = ScanConfig::default();
    config.enable_port_scanner = false;
    let detectors = registry.create_enabled(&config);
    assert!(detectors.is_empty());
}
