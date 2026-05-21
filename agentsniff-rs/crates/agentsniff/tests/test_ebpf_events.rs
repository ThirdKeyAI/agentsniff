use agentsniff_common::*;

#[test]
fn test_dns_event_layout() {
    let event = DnsEvent {
        src_addr: 0x0A000001,
        dst_addr: 0x0A000002,
        query_name: [0u8; 256],
        query_len: 10,
        timestamp_ns: 12345,
    };
    assert_eq!(event.src_addr, 0x0A000001);
    assert_eq!(event.query_len, 10);
    // Verify struct is repr(C) and reasonable size
    assert!(std::mem::size_of::<DnsEvent>() >= 274);
}

#[test]
fn test_conn_event_layout() {
    let event = ConnEvent {
        src_addr: 0x0A000001,
        dst_addr: 0x0A000002,
        dst_port: 443,
        state: TCP_SYN_SENT,
        timestamp_ns: 99999,
    };
    assert_eq!(event.dst_port, 443);
    assert_eq!(event.state, 2);
    assert!(std::mem::size_of::<ConnEvent>() >= 15);
}

#[test]
fn test_tls_event_layout() {
    let mut event = TlsEvent {
        src_addr: 0x0A000001,
        dst_addr: 0x0A000002,
        dst_port: 443,
        tls_version: 0x0303,
        cipher_suites: [0u16; 64],
        cipher_count: 2,
        extensions: [0u16; 64],
        extension_count: 3,
        timestamp_ns: 12345,
    };
    event.cipher_suites[0] = 0x1301;
    event.cipher_suites[1] = 0x1302;
    event.extensions[0] = 0x0000; // server_name
    event.extensions[1] = 0x0033; // key_share
    event.extensions[2] = 0x002B; // supported_versions

    assert_eq!(event.cipher_count, 2);
    assert_eq!(event.extension_count, 3);
    assert_eq!(event.cipher_suites[0], 0x1301);
    assert_eq!(event.extensions[2], 0x002B);
}

#[test]
fn test_traffic_event_layout() {
    let event = TrafficEvent {
        src_addr: 0x0A000001,
        dst_addr: 0x0A000002,
        dst_port: 443,
        pkt_len: 1500,
        direction: TRAFFIC_DIR_EGRESS,
        timestamp_ns: 99999,
    };
    assert_eq!(event.direction, 0);
    assert_eq!(event.pkt_len, 1500);

    let ingress = TrafficEvent {
        direction: TRAFFIC_DIR_INGRESS,
        ..event
    };
    assert_eq!(ingress.direction, 1);
}

#[test]
fn test_traffic_constants() {
    assert_eq!(TRAFFIC_DIR_EGRESS, 0);
    assert_eq!(TRAFFIC_DIR_INGRESS, 1);
}

#[test]
fn test_tcp_state_constants() {
    assert_eq!(TCP_ESTABLISHED, 1);
    assert_eq!(TCP_SYN_SENT, 2);
    assert_eq!(TCP_CLOSE, 7);
}

#[test]
fn test_event_copy_semantics() {
    let event = TrafficEvent {
        src_addr: 1,
        dst_addr: 2,
        dst_port: 80,
        pkt_len: 100,
        direction: 0,
        timestamp_ns: 555,
    };
    let copy = event;
    assert_eq!(copy.src_addr, event.src_addr);
    assert_eq!(copy.timestamp_ns, event.timestamp_ns);
}
