use agentsniff::integrations::enrich::{
    apply_services, parse_httpx_json, parse_naabu_json, parse_zgrab2_json, ObservedService,
};
use agentsniff::integrations::nmap::{
    apply_nmap_xml, classify_service, parse_nmap_xml, ServiceClass,
};
use agentsniff::integrations::zeek::{
    detect_format, parse_conn_line, parse_dns_line, parse_ssl_line, ZeekFormat,
};
use agentsniff::integrations::{DnsRecord, TlsRecord, TrafficRecord};
use agentsniff::models::{
    Confidence, DetectedAgent, DetectorType, Signal, NON_AGENT_SERVICES_SIGNAL,
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
        "ts".to_string(),
        "uid".to_string(),
        "id.orig_h".to_string(),
        "id.orig_p".to_string(),
        "id.resp_h".to_string(),
        "id.resp_p".to_string(),
        "proto".to_string(),
        "duration".to_string(),
        "orig_bytes".to_string(),
        "resp_bytes".to_string(),
    ];
    let line =
        "1711612800.000000\tCabc\t192.168.1.10\t54321\t10.0.0.1\t443\ttcp\t1.500000\t1024\t8192";
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
        "ts".to_string(),
        "uid".to_string(),
        "id.orig_h".to_string(),
        "id.orig_p".to_string(),
        "id.resp_h".to_string(),
        "id.resp_p".to_string(),
        "proto".to_string(),
        "duration".to_string(),
        "orig_bytes".to_string(),
        "resp_bytes".to_string(),
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

const NAABU: &str = include_str!("fixtures/enrich/naabu.jsonl");
const HTTPX: &str = include_str!("fixtures/enrich/httpx.jsonl");
const ZGRAB2: &str = include_str!("fixtures/enrich/zgrab2.jsonl");

#[test]
fn test_parse_naabu_dedups_ports() {
    let open = parse_naabu_json(NAABU);
    assert_eq!(open.len(), 4);
    assert!(open.contains(&("192.0.2.10".to_string(), 8000)));
    assert!(open.contains(&("192.0.2.20".to_string(), 6379)));
}

#[test]
fn test_parse_httpx_skips_failed_and_splits_server() {
    let services = parse_httpx_json(HTTPX);
    assert_eq!(services.len(), 2);
    let (ip, uvicorn) = &services[0];
    assert_eq!(ip, "192.0.2.10");
    assert_eq!(uvicorn.port, 8000);
    assert!(uvicorn.names.contains(&"fastapi".to_string()));
    assert!(uvicorn.names.contains(&"uvicorn".to_string()));
    let (_, cups) = &services[1];
    assert!(cups.names.contains(&"cups".to_string()));
    assert!(cups.names.contains(&"ipp".to_string()));
}

#[test]
fn test_parse_zgrab2_uses_successful_module() {
    let services = parse_zgrab2_json(ZGRAB2);
    assert_eq!(
        services,
        vec![
            (
                "192.0.2.10".to_string(),
                ObservedService {
                    port: 22,
                    names: vec!["ssh".to_string()]
                }
            ),
            (
                "192.0.2.20".to_string(),
                ObservedService {
                    port: 6379,
                    names: vec!["redis".to_string()]
                }
            ),
        ]
    );
}

fn agent(ip: &str) -> DetectedAgent {
    let mut a = DetectedAgent::new(ip.to_string(), ip.parse().unwrap());
    a.confidence_score = 0.8;
    a
}

#[test]
fn test_apply_services_agent_like_adds_signal() {
    let mut a = agent("192.0.2.10");
    let services: Vec<ObservedService> = parse_httpx_json(HTTPX)
        .into_iter()
        .filter(|(ip, _)| ip == "192.0.2.10")
        .map(|(_, s)| s)
        .collect();
    apply_services(
        &mut a,
        &services,
        DetectorType::ServiceEnricher,
        "service_match",
    );
    assert!(a
        .signals
        .iter()
        .any(|s| s.detector == DetectorType::ServiceEnricher && s.signal_type == "service_match"));
}

/// An agent seen only by the port scanner (Medium -> score 0.5).
fn port_scanned_agent(ip: &str) -> DetectedAgent {
    let mut a = DetectedAgent::new(ip.to_string(), ip.parse().unwrap());
    a.signals.push(Signal::new(
        DetectorType::PortScanner,
        "agent_port".to_string(),
        "Agent-like port open".to_string(),
        Confidence::Medium,
        serde_json::json!({}),
    ));
    a.update_status();
    a
}

fn services_for(ip: &str) -> Vec<ObservedService> {
    let mut services: Vec<ObservedService> = parse_httpx_json(HTTPX)
        .into_iter()
        .chain(parse_zgrab2_json(ZGRAB2))
        .filter(|(i, _)| i == ip)
        .map(|(_, s)| s)
        .collect();
    services.sort_by_key(|s| s.port);
    services
}

#[test]
fn test_all_non_agent_services_halve_score_through_recomputes() {
    let mut a = port_scanned_agent("192.0.2.20");
    assert_eq!(a.confidence_score, 0.5);
    let services = services_for("192.0.2.20");
    assert_eq!(services.len(), 2);
    apply_services(
        &mut a,
        &services,
        DetectorType::ServiceEnricher,
        "service_match",
    );
    assert_eq!(a.confidence_score, 0.25);
    // The scanner, storage and dashboard all recompute; the reduction must stick.
    for _ in 0..3 {
        a.update_status();
    }
    assert_eq!(a.confidence_score, 0.25);
    let penalty: Vec<_> = a
        .signals
        .iter()
        .filter(|s| s.signal_type == NON_AGENT_SERVICES_SIGNAL)
        .collect();
    assert_eq!(penalty.len(), 1);
    assert!(penalty[0].evidence["services"].is_array());
    // Applying again (e.g. --enrich plus --nmap-xml) does not halve twice.
    apply_services(
        &mut a,
        &services,
        DetectorType::NmapEnricher,
        "nmap_service_match",
    );
    assert_eq!(a.confidence_score, 0.25);
}

#[test]
fn test_unknown_or_agent_like_service_keeps_score() {
    let unknown = ObservedService {
        port: 9999,
        names: vec!["some-custom-app".to_string()],
    };
    let redis = ObservedService {
        port: 6379,
        names: vec!["redis".to_string()],
    };
    let mut a = port_scanned_agent("192.0.2.30");
    apply_services(
        &mut a,
        &[redis.clone(), unknown],
        DetectorType::ServiceEnricher,
        "service_match",
    );
    a.update_status();
    assert_eq!(a.confidence_score, 0.5);

    let mut b = port_scanned_agent("192.0.2.10");
    apply_services(
        &mut b,
        &services_for("192.0.2.10"),
        DetectorType::ServiceEnricher,
        "service_match",
    );
    b.update_status();
    assert!(b.confidence_score > 0.5);
    assert!(!b
        .signals
        .iter()
        .any(|s| s.signal_type == NON_AGENT_SERVICES_SIGNAL));
}

#[test]
fn test_nmap_xml_import_applies_same_reduction() {
    let xml = r#"<nmaprun><host><address addr="192.0.2.20" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="631"><state state="open"/><service name="ipp" product="CUPS"/></port>
</ports></host></nmaprun>"#;
    let mut agents = vec![port_scanned_agent("192.0.2.20")];
    apply_nmap_xml(&mut agents, xml);
    agents[0].update_status();
    assert_eq!(agents[0].confidence_score, 0.25);
}

#[test]
fn test_stored_agent_from_before_fix_deserializes_unchanged() {
    // An agent serialized by 2.3.0: no non_agent_services signal.
    let json = serde_json::to_string(&port_scanned_agent("192.0.2.40")).unwrap();
    let mut restored: DetectedAgent = serde_json::from_str(&json).unwrap();
    restored.update_status();
    assert_eq!(restored.confidence_score, 0.5);
}

#[test]
fn test_apply_services_empty_leaves_agent_unchanged() {
    let mut a = agent("192.0.2.30");
    apply_services(&mut a, &[], DetectorType::ServiceEnricher, "service_match");
    assert_eq!(a.confidence_score, 0.8);
}

#[test]
fn test_apply_nmap_xml_import() {
    let xml = r#"<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8000"><state state="open"/><service name="http" product="uvicorn"/></port>
</ports></host></nmaprun>"#;
    let mut agents = vec![agent("192.0.2.10"), agent("192.0.2.99")];
    apply_nmap_xml(&mut agents, xml);
    assert!(
        agents[0]
            .signals
            .iter()
            .any(|s| s.detector == DetectorType::NmapEnricher
                && s.signal_type == "nmap_service_match")
    );
    assert!(agents[0].metadata["nmap_services"].is_array());
    assert!(agents[1].signals.is_empty());
}
