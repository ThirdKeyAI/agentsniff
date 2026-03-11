use agentsniff::detectors::tls_fingerprint::compute_ja3_string;

#[test]
fn test_ja3_string_computation() {
    let result = compute_ja3_string(0x0303, &[0xc02c, 0xc02b], &[0x0000, 0x000a]);
    assert_eq!(result, "771,49196-49195,0-10");
}

#[test]
fn test_ja3_string_empty() {
    let result = compute_ja3_string(0x0301, &[], &[]);
    assert_eq!(result, "769,,");
}

#[test]
fn test_ja3_string_single_cipher() {
    let result = compute_ja3_string(0x0303, &[0x1301], &[]);
    assert_eq!(result, "771,4865,");
}

#[tokio::test]
async fn test_tls_detector_scan_empty_targets() {
    use agentsniff::config::ScanConfig;
    use agentsniff::detectors::tls_fingerprint::TlsFingerprintDetector;
    use agentsniff::detectors::Detector;

    let config = ScanConfig::default();
    let detector = TlsFingerprintDetector::new(&config);
    let signals = detector.scan(&[]).await.unwrap();
    assert!(signals.is_empty());
}
