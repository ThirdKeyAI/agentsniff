use agentsniff::integrations::nmap::{parse_nmap_xml, classify_service, ServiceClass};
use agentsniff::integrations::{DnsRecord, TlsRecord, TrafficRecord};
use agentsniff::integrations::zeek::{
    detect_format, parse_conn_line, parse_dns_line, parse_ssl_line, ZeekFormat,
};
use std::net::IpAddr;

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

#[test]
fn test_detect_format_json() {
    let line = r#"{"ts":1711612800.0,"uid":"abc"}"#;
    assert_eq!(detect_format(line), ZeekFormat::Json);
}

#[test]
fn test_detect_format_tsv() {
    let line = "1711612800.000000\tCabc\t192.168.1.10\t54321\t10.0.0.1\t443\ttcp";
    assert_eq!(detect_format(line), ZeekFormat::Tsv);
}

#[test]
fn test_parse_conn_json() {
    let fields = &[];
    let line = r#"{"ts":1711612800.0,"id.orig_h":"192.168.1.10","id.resp_h":"10.0.0.1","id.orig_p":54321,"id.resp_p":443,"proto":"tcp","duration":1.5,"orig_bytes":1024,"resp_bytes":8192}"#;
    let rec = parse_conn_line(line, fields, ZeekFormat::Json);
    assert!(rec.is_some());
    let rec = rec.unwrap();
    assert_eq!(rec.src_ip, "192.168.1.10".parse::<IpAddr>().unwrap());
    assert_eq!(rec.dst_port, 443);
    assert_eq!(rec.bytes_recv, 8192);
}

#[test]
fn test_parse_conn_tsv() {
    let fields = vec![
        "ts".to_string(), "uid".to_string(),
        "id.orig_h".to_string(), "id.orig_p".to_string(),
        "id.resp_h".to_string(), "id.resp_p".to_string(),
        "proto".to_string(), "duration".to_string(),
        "orig_bytes".to_string(), "resp_bytes".to_string(),
    ];
    let line = "1711612800.000000\tCabc\t192.168.1.10\t54321\t10.0.0.1\t443\ttcp\t1.500000\t1024\t8192";
    let rec = parse_conn_line(line, &fields, ZeekFormat::Tsv);
    assert!(rec.is_some());
    let rec = rec.unwrap();
    assert_eq!(rec.dst_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(rec.protocol, "tcp");
}

#[test]
fn test_parse_dns_json() {
    let fields = &[];
    let line = r#"{"ts":1711612800.0,"id.orig_h":"192.168.1.10","query":"api.openai.com","qtype_name":"A","answers":["104.18.1.1","104.18.2.2"]}"#;
    let rec = parse_dns_line(line, fields, ZeekFormat::Json);
    assert!(rec.is_some());
    let rec = rec.unwrap();
    assert_eq!(rec.query, "api.openai.com");
    assert_eq!(rec.response_ips.len(), 2);
}

#[test]
fn test_parse_ssl_json() {
    let fields = &[];
    let line = r#"{"ts":1711612800.0,"id.orig_h":"192.168.1.10","id.resp_h":"10.0.0.1","server_name":"api.anthropic.com","ja3":"abc123","subject":"CN=api.anthropic.com","issuer":"CN=DigiCert"}"#;
    let rec = parse_ssl_line(line, fields, ZeekFormat::Json);
    assert!(rec.is_some());
    let rec = rec.unwrap();
    assert_eq!(rec.server_name.as_deref(), Some("api.anthropic.com"));
    assert_eq!(rec.ja3_hash.as_deref(), Some("abc123"));
}

#[test]
fn test_parse_tsv_skips_comments() {
    let fields = vec!["ts".to_string(), "uid".to_string()];
    let line = "#separator \\x09";
    let rec = parse_conn_line(line, &fields, ZeekFormat::Tsv);
    assert!(rec.is_none());
}

#[test]
fn test_parse_tsv_dash_means_empty() {
    let fields = vec![
        "ts".to_string(), "uid".to_string(),
        "id.orig_h".to_string(), "id.orig_p".to_string(),
        "id.resp_h".to_string(), "id.resp_p".to_string(),
        "proto".to_string(), "duration".to_string(),
        "orig_bytes".to_string(), "resp_bytes".to_string(),
    ];
    let line = "1711612800.000000\tCabc\t192.168.1.10\t54321\t10.0.0.1\t443\ttcp\t-\t-\t-";
    let rec = parse_conn_line(line, &fields, ZeekFormat::Tsv);
    assert!(rec.is_some());
    let rec = rec.unwrap();
    assert!(rec.duration.is_none());
    assert_eq!(rec.bytes_sent, 0);
}

#[test]
fn test_classify_agent_like_service() {
    assert_eq!(classify_service("uvicorn"), ServiceClass::AgentLike);
    assert_eq!(classify_service("ollama"), ServiceClass::AgentLike);
    assert_eq!(classify_service("fastapi"), ServiceClass::AgentLike);
    assert_eq!(classify_service("gunicorn"), ServiceClass::AgentLike);
}

#[test]
fn test_classify_non_agent_service() {
    assert_eq!(classify_service("sshd"), ServiceClass::NonAgent);
    assert_eq!(classify_service("postgresql"), ServiceClass::NonAgent);
    assert_eq!(classify_service("nginx"), ServiceClass::NonAgent);
    assert_eq!(classify_service("cups"), ServiceClass::NonAgent);
}

#[test]
fn test_classify_unknown_service() {
    assert_eq!(classify_service("some-custom-app"), ServiceClass::Unknown);
}

#[test]
fn test_parse_nmap_xml() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8000">
        <state state="open"/>
        <service name="http" product="uvicorn" version="0.30.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.7"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
    let hosts = parse_nmap_xml(xml);
    assert_eq!(hosts.len(), 1);
    let host = &hosts[0];
    assert_eq!(host.ip, "192.168.1.10");
    assert_eq!(host.services.len(), 2);
    assert_eq!(host.services[0].product.as_deref(), Some("uvicorn"));
    assert_eq!(host.services[0].port, 8000);
    assert_eq!(host.services[1].product.as_deref(), Some("OpenSSH"));
}
