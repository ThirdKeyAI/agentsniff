#![cfg_attr(not(feature = "user"), no_std)]

/// DNS query event from eBPF TC hook.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub query_name: [u8; 256],
    pub query_len: u16,
    pub timestamp_ns: u64,
}

/// TCP connection event from eBPF kprobe/tracepoint.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub state: u8,
    pub timestamp_ns: u64,
}

/// TLS ClientHello event from eBPF TC hook.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub tls_version: u16,
    pub cipher_suites: [u16; 64],
    pub cipher_count: u8,
    pub extensions: [u16; 64],
    pub extension_count: u8,
    pub timestamp_ns: u64,
}

/// Packet timing event from eBPF TC hook (ingress + egress).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrafficEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub pkt_len: u16,
    pub direction: u8, // 0 = egress, 1 = ingress
    pub timestamp_ns: u64,
}

pub const TRAFFIC_DIR_EGRESS: u8 = 0;
pub const TRAFFIC_DIR_INGRESS: u8 = 1;

pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_SYN_SENT: u8 = 2;
pub const TCP_CLOSE: u8 = 7;
