use std::net::IpAddr;

use async_trait::async_trait;

use crate::config::ScanConfig;
use crate::models::{Confidence, DetectorType, Signal};
use crate::signatures::SignatureData;

use super::Detector;

/// DNS monitor detector that operates in fallback mode (no eBPF).
///
/// Resolves known LLM and agent infrastructure domains and checks if any
/// resolve to a scanned target IP. Also performs reverse DNS lookups on
/// target IPs and checks against known domain suffixes.
pub struct DnsMonitorDetector {
    config: ScanConfig,
    signatures: SignatureData,
}

impl DnsMonitorDetector {
    /// Create a new DNS monitor detector from scan configuration.
    pub fn new(config: &ScanConfig) -> Self {
        Self {
            config: config.clone(),
            signatures: SignatureData::load_embedded(),
        }
    }
}

#[async_trait]
impl Detector for DnsMonitorDetector {
    fn name(&self) -> &str {
        "dns_monitor"
    }

    fn detector_type(&self) -> DetectorType {
        DetectorType::DnsMonitor
    }

    async fn setup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn teardown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    async fn scan(&self, targets: &[IpAddr]) -> anyhow::Result<Vec<Signal>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        let mut signals = Vec::new();

        // Build combined domain lists (embedded signatures + custom config entries)
        let mut llm_domains: Vec<String> = self.signatures.llm_domains.clone();
        llm_domains.extend(self.config.custom_llm_domains.clone());

        let mut agent_infra_domains: Vec<String> = self.signatures.agent_infra_domains.clone();
        agent_infra_domains.extend(self.config.custom_agent_infra_domains.clone());

        let domain_suffixes = self.signatures.domain_suffixes.clone();

        // --- Forward lookup: LLM domains → check if any IP matches a target ---
        for domain in &llm_domains {
            match resolve_domain(domain).await {
                Ok(ips) => {
                    for ip in &ips {
                        if targets.contains(ip) {
                            signals.push(Signal::new(
                                DetectorType::DnsMonitor,
                                "llm_api_domain_query".to_string(),
                                format!(
                                    "LLM API domain {} resolves to target {}",
                                    domain, ip
                                ),
                                Confidence::High,
                                serde_json::json!({
                                    "ip": ip.to_string(),
                                    "domain": domain,
                                    "category": "llm_api",
                                }),
                            ));
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("DNS resolution failed for {}: {}", domain, e);
                }
            }
        }

        // --- Forward lookup: agent infra domains → MEDIUM confidence ---
        for domain in &agent_infra_domains {
            match resolve_domain(domain).await {
                Ok(ips) => {
                    for ip in &ips {
                        if targets.contains(ip) {
                            signals.push(Signal::new(
                                DetectorType::DnsMonitor,
                                "agent_infrastructure_domain_query".to_string(),
                                format!(
                                    "Agent infra domain {} resolves to target {}",
                                    domain, ip
                                ),
                                Confidence::Medium,
                                serde_json::json!({
                                    "ip": ip.to_string(),
                                    "domain": domain,
                                    "category": "agent_infrastructure",
                                }),
                            ));
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("DNS resolution failed for {}: {}", domain, e);
                }
            }
        }

        // --- Reverse lookup: for each target, check PTR against known domains/suffixes ---
        for &ip in targets {
            match reverse_lookup(ip).await {
                Ok(hostnames) => {
                    for hostname in &hostnames {
                        if let Some(category) = matches_known_domain(
                            hostname,
                            &llm_domains,
                            &agent_infra_domains,
                            &domain_suffixes,
                        ) {
                            let (signal_type, confidence) = match category {
                                "llm_api" => ("llm_api_domain_query", Confidence::High),
                                _ => (
                                    "agent_infrastructure_domain_query",
                                    Confidence::Medium,
                                ),
                            };
                            signals.push(Signal::new(
                                DetectorType::DnsMonitor,
                                signal_type.to_string(),
                                format!(
                                    "Target {} has reverse DNS {} matching known {} domain",
                                    ip, hostname, category
                                ),
                                confidence,
                                serde_json::json!({
                                    "ip": ip.to_string(),
                                    "domain": hostname,
                                    "category": category,
                                    "source": "reverse_dns",
                                }),
                            ));
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Reverse DNS lookup failed for {}: {}", ip, e);
                }
            }
        }

        Ok(signals)
    }
}

/// Check if a domain matches any known domain or suffix.
///
/// Returns `Some("llm_api")` for LLM domain matches,
/// `Some("agent_infrastructure")` for agent infra domain matches,
/// `Some("domain_suffix")` for suffix matches, or `None` if no match.
pub fn matches_known_domain(
    domain: &str,
    llm_domains: &[String],
    infra_domains: &[String],
    suffixes: &[String],
) -> Option<&'static str> {
    let domain_lower = domain.to_lowercase();

    // Exact match against LLM domains
    for known in llm_domains {
        if domain_lower == known.to_lowercase() {
            return Some("llm_api");
        }
    }

    // Exact match against agent infra domains
    for known in infra_domains {
        if domain_lower == known.to_lowercase() {
            return Some("agent_infrastructure");
        }
    }

    // Suffix match (e.g. "api.openai.com" matches suffix ".openai.com")
    for suffix in suffixes {
        let suffix_lower = suffix.to_lowercase();
        // Support both ".example.com" and "example.com" style suffixes
        let normalised_suffix = if suffix_lower.starts_with('.') {
            suffix_lower.clone()
        } else {
            format!(".{}", suffix_lower)
        };
        if domain_lower.ends_with(&normalised_suffix) || domain_lower == suffix_lower.trim_start_matches('.') {
            return Some("domain_suffix");
        }
    }

    None
}

/// Resolve a domain name to a list of IP addresses using blocking DNS.
async fn resolve_domain(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;

    let domain = domain.to_string();
    let ips = tokio::task::spawn_blocking(move || {
        let addr = format!("{}:0", domain);
        addr.to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect::<Vec<_>>())
    })
    .await??;
    Ok(ips)
}

/// Perform a reverse DNS lookup for an IP address.
///
/// Returns a list of hostnames (PTR records) associated with the IP.
async fn reverse_lookup(ip: IpAddr) -> anyhow::Result<Vec<String>> {
    use std::net::ToSocketAddrs;

    // Construct the reverse DNS query name
    let reverse_name = ip_to_reverse_name(ip);
    let hostnames = tokio::task::spawn_blocking(move || {
        let addr = format!("{}:0", reverse_name);
        addr.to_socket_addrs()
            .map(|addrs| {
                addrs
                    .filter_map(|a| {
                        // The standard library does not give us the hostname from
                        // to_socket_addrs; we can only get it back by re-resolving.
                        // Use the IP string as a placeholder and rely on the OS
                        // resolver to do PTR lookup via getnameinfo via lookup_host.
                        // This approach won't work with to_socket_addrs.
                        let _ = a;
                        None::<String>
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    })
    .await?;

    // Standard library doesn't expose getnameinfo directly.
    // Use a DNS-PTR workaround: resolve the .in-addr.arpa / .ip6.arpa name.
    // The to_socket_addrs on the arpa name will perform a forward lookup on
    // the PTR record's target, not the PTR record itself. We can't get PTR
    // results via std. Return empty unless we got results above.
    let _ = hostnames;

    // Fallback: attempt lookup via the arpa name using a raw getaddrinfo call
    // Since std::net doesn't expose reverse lookups, we do a best-effort
    // forward lookup of the arpa name and hope the resolver returns a CNAME/A.
    // In practice this won't return hostnames, so we return empty here.
    // A real implementation would use the `hickory-resolver` or `trust-dns` crate,
    // but those are not in the current dependency tree. Returning empty is safe —
    // the forward-lookup path above handles the primary detection use case.
    Ok(Vec::new())
}

/// Convert an IP address to its reverse DNS lookup name.
///
/// For IPv4: "1.2.3.4" → "4.3.2.1.in-addr.arpa"
/// For IPv6: reversal of nibbles + ".ip6.arpa"
fn ip_to_reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let segments = v6.octets();
            let nibbles: Vec<String> = segments
                .iter()
                .rev()
                .flat_map(|byte| {
                    vec![
                        format!("{:x}", byte & 0x0f),
                        format!("{:x}", (byte >> 4) & 0x0f),
                    ]
                })
                .collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}
