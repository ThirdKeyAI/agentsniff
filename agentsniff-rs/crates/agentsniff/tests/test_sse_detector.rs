use agentsniff::config::ScanConfig;
use agentsniff::detectors::sse_detector::*;
use agentsniff::detectors::Detector;
use agentsniff::models::DetectorType;

#[test]
fn test_sse_detector_name() {
    let config = ScanConfig::default();
    let detector = SseDetector::new(&config);
    assert_eq!(detector.name(), "sse_detector");
    assert_eq!(detector.detector_type(), DetectorType::SseDetector);
}

#[tokio::test]
async fn test_scan_returns_empty() {
    let config = ScanConfig::default();
    let detector = SseDetector::new(&config);
    let targets = vec!["192.168.1.1".parse().unwrap()];
    let signals = detector.scan(&targets).await.unwrap();
    assert!(signals.is_empty());
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
fn test_timing_analysis_too_few_packets() {
    let analysis = PacketTimingAnalysis {
        packet_count: 5,
        median_size: 100.0,
        median_inter_arrival_ms: 50.0,
    };
    assert!(analysis.analyze().is_none());
}

#[test]
fn test_timing_analysis_large_packets() {
    let analysis = PacketTimingAnalysis {
        packet_count: 50,
        median_size: 1500.0,
        median_inter_arrival_ms: 50.0,
    };
    assert!(analysis.analyze().is_none());
}

#[test]
fn test_timing_analysis_wrong_cadence() {
    let analysis = PacketTimingAnalysis {
        packet_count: 50,
        median_size: 100.0,
        median_inter_arrival_ms: 500.0,
    };
    assert!(analysis.analyze().is_none());
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
