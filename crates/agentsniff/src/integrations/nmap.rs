//! Nmap XML import: parses a user's own Nmap XML results and adds/adjusts signals.
//!
//! AgentSniff never executes Nmap. This module only reads results the user
//! produced themselves (`nmap -oX`).

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use super::enrich::{apply_services, ObservedService};
pub use super::enrich::{classify_service, ServiceClass};
use crate::models::{DetectedAgent, DetectorType};

/// Largest Nmap XML file accepted for import.
pub const MAX_NMAP_XML_BYTES: usize = 64 * 1024 * 1024;

/// Read a user's Nmap XML file, refusing files over `MAX_NMAP_XML_BYTES`.
pub fn read_nmap_xml(path: &str) -> anyhow::Result<String> {
    let bytes = crate::agentpin::read_bounded_path(
        std::path::Path::new(path),
        MAX_NMAP_XML_BYTES,
        "Nmap XML",
    )?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// A single open service discovered by nmap.
#[derive(Debug, Clone)]
pub struct NmapService {
    pub port: u16,
    pub protocol: String,
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub state: String,
}

/// A host with its open services as discovered by nmap.
#[derive(Debug, Clone)]
pub struct NmapHost {
    pub ip: String,
    pub services: Vec<NmapService>,
}

/// Parse nmap XML output (from `nmap -oX -`) into a list of hosts.
pub fn parse_nmap_xml(xml: &str) -> Vec<NmapHost> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut hosts: Vec<NmapHost> = Vec::new();

    let mut in_host = false;
    let mut current_ip: Option<String> = None;
    let mut current_services: Vec<NmapService> = Vec::new();

    // Per-port state
    let mut current_port: Option<u16> = None;
    let mut current_protocol: Option<String> = None;
    let mut current_state: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = e.name();
                let tag = std::str::from_utf8(name.as_ref()).unwrap_or("");

                match tag {
                    "host" => {
                        in_host = true;
                        current_ip = None;
                        current_services = Vec::new();
                        current_port = None;
                        current_protocol = None;
                        current_state = None;
                    }
                    "address" if in_host => {
                        let mut addr_val: Option<String> = None;
                        let mut addr_type: Option<String> = None;
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            let val = attr
                                .normalized_value(XmlVersion::Implicit1_0)
                                .unwrap_or_default()
                                .into_owned();
                            match key {
                                "addr" => addr_val = Some(val),
                                "addrtype" => addr_type = Some(val),
                                _ => {}
                            }
                        }
                        if addr_type.as_deref() == Some("ipv4") {
                            current_ip = addr_val;
                        }
                    }
                    "port" if in_host => {
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            let val = attr
                                .normalized_value(XmlVersion::Implicit1_0)
                                .unwrap_or_default()
                                .into_owned();
                            match key {
                                "portid" => {
                                    current_port = val.parse().ok();
                                }
                                "protocol" => {
                                    current_protocol = Some(val);
                                }
                                _ => {}
                            }
                        }
                        current_state = None;
                    }
                    "state" if in_host => {
                        for attr in e.attributes().flatten() {
                            let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                            let val = attr
                                .normalized_value(XmlVersion::Implicit1_0)
                                .unwrap_or_default()
                                .into_owned();
                            if key == "state" {
                                current_state = Some(val);
                            }
                        }
                    }
                    "service" if in_host => {
                        if let Some(port) = current_port {
                            let mut svc_name: Option<String> = None;
                            let mut product: Option<String> = None;
                            let mut version: Option<String> = None;
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
                                let val = attr
                                    .normalized_value(XmlVersion::Implicit1_0)
                                    .unwrap_or_default()
                                    .into_owned();
                                match key {
                                    "name" => svc_name = Some(val),
                                    "product" => product = Some(val),
                                    "version" => version = Some(val),
                                    _ => {}
                                }
                            }
                            let svc = NmapService {
                                port,
                                protocol: current_protocol
                                    .clone()
                                    .unwrap_or_else(|| "tcp".to_string()),
                                name: svc_name,
                                product,
                                version,
                                state: current_state.clone().unwrap_or_else(|| "open".to_string()),
                            };
                            current_services.push(svc);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name_end = e.name();
                let tag = std::str::from_utf8(name_end.as_ref()).unwrap_or("");
                match tag {
                    "host" if in_host => {
                        if let Some(ip) = current_ip.take() {
                            hosts.push(NmapHost {
                                ip,
                                services: std::mem::take(&mut current_services),
                            });
                        }
                        in_host = false;
                        current_port = None;
                        current_protocol = None;
                        current_state = None;
                    }
                    "port" => {
                        current_port = None;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    hosts
}

/// Apply a user's own Nmap XML results to detected agents. Hosts in the XML
/// that are not already detected agents are ignored.
pub fn apply_nmap_xml(agents: &mut [DetectedAgent], xml: &str) {
    let hosts = parse_nmap_xml(xml);
    for agent in agents {
        let ip = agent.ip_address.to_string();
        let Some(host) = hosts.iter().find(|h| h.ip == ip) else {
            continue;
        };

        let services_json: Vec<serde_json::Value> = host
            .services
            .iter()
            .map(|s| {
                serde_json::json!({
                    "port": s.port,
                    "protocol": s.protocol,
                    "name": s.name,
                    "product": s.product,
                    "version": s.version,
                    "state": s.state,
                })
            })
            .collect();
        if let Some(obj) = agent.metadata.as_object_mut() {
            obj.insert(
                "nmap_services".to_string(),
                serde_json::json!(services_json),
            );
        }

        // Product first, then service name, matching Nmap's own precedence.
        let observed: Vec<ObservedService> = host
            .services
            .iter()
            .map(|s| ObservedService {
                port: s.port,
                names: s.product.iter().chain(s.name.iter()).cloned().collect(),
            })
            .collect();
        apply_services(
            agent,
            &observed,
            DetectorType::NmapEnricher,
            "nmap_service_match",
        );
    }
}
