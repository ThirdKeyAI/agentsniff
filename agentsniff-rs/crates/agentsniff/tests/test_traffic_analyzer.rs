use agentsniff::config::ScanConfig;
use agentsniff::detectors::traffic_analyzer::{
    parse_hex_addr, parse_proc_tcp_line, TrafficAnalyzerDetector,
};
use agentsniff::detectors::Detector;

#[test]
fn test_parse_hex_addr_loopback() {
    // 0100007F:0050 = 127.0.0.1:80 (little-endian IP in /proc/net/tcp)
    let result = parse_hex_addr("0100007F:0050");
    assert!(result.is_some());
    let (ip, port) = result.unwrap();
    assert_eq!(port, 80);
    // Verify it parsed to the loopback address
    assert_eq!(ip.to_string(), "127.0.0.1");
}

#[test]
fn test_parse_hex_addr_invalid() {
    assert!(parse_hex_addr("invalid").is_none());
    assert!(parse_hex_addr("").is_none());
    assert!(parse_hex_addr("ZZZZZZZZ:0050").is_none());
}

#[test]
fn test_parse_hex_addr_no_colon() {
    assert!(parse_hex_addr("0100007F").is_none());
}

#[test]
fn test_parse_proc_tcp_line_listen() {
    // Typical /proc/net/tcp LISTEN line (state 0A = 10 = LISTEN)
    let line = "   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
    let result = parse_proc_tcp_line(line);
    assert!(result.is_some());
    let conn = result.unwrap();
    // state 0x0A = 10 (LISTEN)
    assert_eq!(conn.state, 0x0A);
    assert_eq!(conn.local_port, 0x0CEA);
}

#[test]
fn test_parse_proc_tcp_line_established() {
    // State 01 = ESTABLISHED
    let line = "   1: 0F02000A:C3B2 0101007F:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 20 4 24 10 -1";
    let result = parse_proc_tcp_line(line);
    assert!(result.is_some());
    let conn = result.unwrap();
    assert_eq!(conn.state, 0x01);
    // remote port 0x01BB = 443
    assert_eq!(conn.remote_port, 443);
}

#[test]
fn test_parse_proc_tcp_line_invalid() {
    assert!(parse_proc_tcp_line("").is_none());
    assert!(parse_proc_tcp_line("too short").is_none());
    assert!(parse_proc_tcp_line("a b c").is_none());
}

#[tokio::test]
async fn test_traffic_analyzer_scan_empty_targets() {
    let config = ScanConfig::default();
    let detector = TrafficAnalyzerDetector::new(&config);
    let signals = detector.scan(&[]).await.unwrap();
    assert!(signals.is_empty());
}

#[test]
fn test_detector_name_and_type() {
    use agentsniff::models::DetectorType;
    let config = ScanConfig::default();
    let detector = TrafficAnalyzerDetector::new(&config);
    assert_eq!(detector.name(), "traffic_analyzer");
    assert_eq!(detector.detector_type(), DetectorType::TrafficAnalyzer);
}

#[test]
fn test_parse_hex_addr_port_zero() {
    // Port 0 edge case
    let result = parse_hex_addr("00000000:0000");
    assert!(result.is_some());
    let (_, port) = result.unwrap();
    assert_eq!(port, 0);
}
