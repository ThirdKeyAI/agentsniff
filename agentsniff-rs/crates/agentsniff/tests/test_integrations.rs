use agentsniff::integrations::{DnsRecord, TlsRecord, TrafficRecord};

#[test]
fn test_traffic_record_creation() {
    let rec = TrafficRecord {
        timestamp: 1711612800.0,
        src_ip: "192.168.1.10".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        src_port: 54321,
        dst_port: 443,
        protocol: "tcp".to_string(),
        duration: Some(1.5),
        bytes_sent: 1024,
        bytes_recv: 8192,
    };
    assert_eq!(rec.dst_port, 443);
    assert_eq!(rec.bytes_recv, 8192);
}

#[test]
fn test_dns_record_creation() {
    let rec = DnsRecord {
        timestamp: 1711612800.0,
        query: "api.openai.com".to_string(),
        qtype: "A".to_string(),
        response_ips: vec!["104.18.1.1".parse().unwrap()],
        src_ip: "192.168.1.10".parse().unwrap(),
    };
    assert_eq!(rec.query, "api.openai.com");
    assert_eq!(rec.response_ips.len(), 1);
}

#[test]
fn test_tls_record_creation() {
    let rec = TlsRecord {
        timestamp: 1711612800.0,
        src_ip: "192.168.1.10".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        server_name: Some("api.anthropic.com".to_string()),
        ja3_hash: Some("abc123".to_string()),
        subject: None,
        issuer: None,
    };
    assert_eq!(rec.server_name.as_deref(), Some("api.anthropic.com"));
}
