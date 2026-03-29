use agentsniff::detectors::sse_detector::{compute_median, PacketTimingAnalysis, SseDetector};
use agentsniff::config::ScanConfig;
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;

#[test]
fn test_sse_detector_name() {
    let config = ScanConfig::default();
    let detector = SseDetector::new(&config, None);
    assert_eq!(detector.name(), "sse_detector");
    assert_eq!(detector.detector_type(), DetectorType::SseDetector);
}

#[tokio::test]
async fn test_scan_returns_empty() {
    let config = ScanConfig::default();
    let detector = SseDetector::new(&config, None);
    let targets = vec!["192.168.1.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
}

#[test]
fn test_timing_analysis_detects_sse_pattern() {
    let analysis = PacketTimingAnalysis {
        packet_count: 50,
        median_size: 200.0,
        median_inter_arrival_ms: 50.0,
    };
    let confidence = analysis.analyze();
    assert!(confidence.is_some());
    let c = confidence.unwrap();
    // 0.5 + 50/100 = 1.0, clamped to 0.95
    assert!((c - 0.95).abs() < 1e-10);
}

#[test]
fn test_timing_analysis_rejects_too_few_packets() {
    let analysis = PacketTimingAnalysis {
        packet_count: 5,
        median_size: 200.0,
        median_inter_arrival_ms: 50.0,
    };
    assert!(analysis.analyze().is_none());
}

#[test]
fn test_timing_analysis_rejects_large_packets() {
    let analysis = PacketTimingAnalysis {
        packet_count: 50,
        median_size: 600.0,
        median_inter_arrival_ms: 50.0,
    };
    assert!(analysis.analyze().is_none());
}

#[test]
fn test_timing_analysis_rejects_wrong_cadence() {
    let analysis = PacketTimingAnalysis {
        packet_count: 50,
        median_size: 200.0,
        median_inter_arrival_ms: 5.0,
    };
    assert!(analysis.analyze().is_none());

    let analysis = PacketTimingAnalysis {
        packet_count: 50,
        median_size: 200.0,
        median_inter_arrival_ms: 300.0,
    };
    assert!(analysis.analyze().is_none());
}

#[test]
fn test_timing_confidence_capped_at_095() {
    let analysis = PacketTimingAnalysis {
        packet_count: 200,
        median_size: 100.0,
        median_inter_arrival_ms: 50.0,
    };
    let confidence = analysis.analyze().unwrap();
    assert!((confidence - 0.95).abs() < 1e-10);
}

#[test]
fn test_compute_median_odd() {
    let median = compute_median(&mut vec![3.0, 1.0, 2.0]);
    assert!((median - 2.0).abs() < 1e-10);
}

#[test]
fn test_compute_median_even() {
    let median = compute_median(&mut vec![1.0, 2.0, 3.0, 4.0]);
    assert!((median - 2.5).abs() < 1e-10);
}

#[test]
fn test_compute_median_empty() {
    let median = compute_median(&mut vec![]);
    assert!((median - 0.0).abs() < 1e-10);
}

#[test]
fn test_timing_analysis_sse_pattern() {
    let analysis = PacketTimingAnalysis {
        packet_count: 50,
        median_size: 100.0,
        median_inter_arrival_ms: 50.0,
    };
    let confidence = analysis.analyze().unwrap();
    // 0.5 + 50/100 = 1.0, clamped to 0.95
    assert!(confidence <= 0.95);
    assert!((confidence - 0.95).abs() < 0.01);
}

#[test]
fn test_timing_analysis_minimum_viable() {
    let analysis = PacketTimingAnalysis {
        packet_count: 10,
        median_size: 50.0,
        median_inter_arrival_ms: 80.0,
    };
    let confidence = analysis.analyze().unwrap();
    // 0.5 + 10/100 = 0.6
    assert!((confidence - 0.6).abs() < 0.01);
}
