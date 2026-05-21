//! Integration traits and shared record types for external data sources and enrichers.

pub mod nmap;
pub mod zeek;

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::models::DetectedAgent;

/// A record of network traffic between two hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub timestamp: f64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub duration: Option<f64>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// A DNS query record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub timestamp: f64,
    pub query: String,
    pub qtype: String,
    pub response_ips: Vec<IpAddr>,
    pub src_ip: IpAddr,
}

/// A TLS handshake record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecord {
    pub timestamp: f64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub server_name: Option<String>,
    pub ja3_hash: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
}

/// Trait for external data sources that provide historical network records.
#[async_trait]
pub trait DataSource: Send + Sync {
    async fn load_traffic(
        &self,
        targets: &[IpAddr],
        time_window: Duration,
    ) -> anyhow::Result<Vec<TrafficRecord>>;

    async fn load_dns(
        &self,
        targets: &[IpAddr],
        time_window: Duration,
    ) -> anyhow::Result<Vec<DnsRecord>>;

    async fn load_tls(
        &self,
        targets: &[IpAddr],
        time_window: Duration,
    ) -> anyhow::Result<Vec<TlsRecord>>;
}

/// Trait for post-scan enrichers that add metadata or adjust confidence.
#[async_trait]
pub trait Enricher: Send + Sync {
    async fn enrich(&self, agents: Vec<DetectedAgent>) -> anyhow::Result<Vec<DetectedAgent>>;
}
