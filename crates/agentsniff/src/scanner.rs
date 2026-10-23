use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use chrono::Utc;
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::ScanConfig;
use crate::detectors::a2a_detector::A2aDetector;
use crate::detectors::agentpin_prober::AgentpinProber;
use crate::detectors::dns_monitor::DnsMonitorDetector;
use crate::detectors::endpoint_prober::EndpointProberDetector;
use crate::detectors::mcp_detector::McpDetector;
use crate::detectors::port_scanner::PortScannerDetector;
use crate::detectors::sse_detector::SseDetector;
use crate::detectors::tls_fingerprint::TlsFingerprintDetector;
use crate::detectors::traffic_analyzer::TrafficAnalyzerDetector;
use crate::detectors::{Detector, DetectorRegistry};
use crate::ebpf::EbpfChannels;
use crate::fusion::apply_fusion_rules;
use crate::integrations::enrich::ServiceEnricher;
use crate::integrations::nmap::{apply_nmap_xml, read_nmap_xml};
use crate::integrations::zeek::ZeekDataSource;
use crate::integrations::{DataSource, Enricher};
use crate::models::{Confidence, DetectedAgent, DetectorType, ScanResult, Signal};

/// Callback type for reporting detected agents during a scan.
pub type OnAgentCallback = Box<dyn Fn(&DetectedAgent) + Send + Sync>;

/// Maximum number of resolved targets accepted for one scan.
pub const MAX_SCAN_TARGETS: usize = 65_536;

fn scan_scope_id(config: &ScanConfig, targets: &[IpAddr], detectors: &[DetectorType]) -> String {
    let mut targets: Vec<String> = targets.iter().map(ToString::to_string).collect();
    targets.sort();
    let mut detectors: Vec<String> = detectors
        .iter()
        .filter_map(|detector| {
            serde_json::to_value(detector)
                .ok()?
                .as_str()
                .map(str::to_string)
        })
        .collect();
    if config.zeek_enabled && !config.zeek_log_path.is_empty() {
        detectors.push(format!(
            "zeek:{}:{}",
            config.zeek_log_path, config.zeek_time_window
        ));
    }
    if config.enrich_enabled {
        detectors.push("enrich".to_string());
    }
    if !config.nmap_xml_import.is_empty() {
        detectors.push(format!("nmap_xml:{}", config.nmap_xml_import));
    }
    detectors.sort();
    let material = serde_json::to_vec(&serde_json::json!({
        "targets": targets,
        "detectors": detectors,
        "dns_interface": config.dns_interface,
        "ebpf_interface": config.ebpf_interface,
    }))
    .unwrap_or_default();
    let digest = Sha256::digest(material);
    let encoded = digest
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("scope-{encoded}")
}

/// Parse a CIDR notation string and enumerate usable IPv4 addresses.
///
/// For prefixes /31 and smaller (i.e., /31, /30, ... /8), network and broadcast
/// addresses are excluded. For /32, the single host is returned. For /31, both
/// addresses are returned (point-to-point link per RFC 3021).
fn parse_cidr(cidr: &str) -> anyhow::Result<Vec<IpAddr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid CIDR notation: {}", cidr);
    }

    let base_ip: Ipv4Addr = parts[0]
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid IP address '{}': {}", parts[0], e))?;
    let prefix_len: u32 = parts[1]
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid prefix length '{}': {}", parts[1], e))?;

    if prefix_len > 32 {
        anyhow::bail!("prefix length {} is out of range (0-32)", prefix_len);
    }

    // Compute network mask and host count
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let network = u32::from(base_ip) & mask;
    let address_count = 1u64 << (32 - prefix_len);
    let usable_count = match prefix_len {
        32 => 1,
        31 => 2,
        _ => address_count - 2,
    };

    if usable_count > MAX_SCAN_TARGETS as u64 {
        anyhow::bail!(
            "CIDR {} expands to {} targets; maximum is {}",
            cidr,
            usable_count,
            MAX_SCAN_TARGETS
        );
    }

    let mut addrs = Vec::with_capacity(usable_count as usize);

    if prefix_len == 32 {
        addrs.push(IpAddr::V4(base_ip));
    } else if prefix_len == 31 {
        // /31 point-to-point: include both addresses
        for i in 0..address_count {
            let ip = Ipv4Addr::from((network as u64 + i) as u32);
            addrs.push(IpAddr::V4(ip));
        }
    } else {
        // Skip network (first) and broadcast (last)
        for i in 1..(address_count - 1) {
            let ip = Ipv4Addr::from((network as u64 + i) as u32);
            addrs.push(IpAddr::V4(ip));
        }
    }

    Ok(addrs)
}

/// Resolve all target IP addresses from configuration.
///
/// Parses the CIDR network, adds additional target hosts (resolving hostnames),
/// removes excluded hosts, and deduplicates the result.
pub fn resolve_targets(config: &ScanConfig) -> anyhow::Result<Vec<IpAddr>> {
    let mut targets = Vec::new();

    // Parse CIDR network
    if !config.target_network.is_empty() {
        let cidr_addrs = parse_cidr(&config.target_network)?;
        targets.extend(cidr_addrs);
    }

    // Add additional target hosts (may be IPs or hostnames)
    for host in &config.target_hosts {
        if let Ok(ip) = host.parse::<IpAddr>() {
            targets.push(ip);
        } else {
            // Attempt DNS resolution
            use std::net::ToSocketAddrs;
            let addr_str = format!("{}:0", host);
            match addr_str.to_socket_addrs() {
                Ok(addrs) => {
                    for addr in addrs {
                        targets.push(addr.ip());
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to resolve hostname '{}': {}", host, e);
                }
            }
        }
    }

    // Remove excluded hosts
    let exclude_ips: Vec<IpAddr> = config
        .exclude_hosts
        .iter()
        .filter_map(|h| h.parse::<IpAddr>().ok())
        .collect();

    targets.retain(|ip| !exclude_ips.contains(ip));

    // Dedup (preserve order)
    let mut seen = std::collections::HashSet::new();
    targets.retain(|ip| seen.insert(*ip));

    if targets.len() > MAX_SCAN_TARGETS {
        anyhow::bail!(
            "scan resolves to {} targets; maximum is {}",
            targets.len(),
            MAX_SCAN_TARGETS
        );
    }

    Ok(targets)
}

/// Build a detector registry with all active detectors.
pub fn build_registry() -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();

    registry.register("dns_monitor", "enable_dns_monitor", |config, channels| {
        Box::new(DnsMonitorDetector::new(config, channels))
    });

    registry.register(
        "port_scanner",
        "enable_port_scanner",
        |config, _channels| Box::new(PortScannerDetector::new(config)),
    );

    registry.register(
        "endpoint_prober",
        "enable_endpoint_prober",
        |config, _channels| Box::new(EndpointProberDetector::new(config)),
    );

    registry.register(
        "mcp_detector",
        "enable_mcp_detector",
        |config, _channels| Box::new(McpDetector::new(config)),
    );

    registry.register(
        "a2a_detector",
        "enable_a2a_detector",
        |config, _channels| Box::new(A2aDetector::new(config)),
    );

    registry.register(
        "agentpin_prober",
        "enable_agentpin_prober",
        |config, _channels| Box::new(AgentpinProber::new(config)),
    );

    registry.register("sse_detector", "enable_sse_detector", |config, channels| {
        Box::new(SseDetector::new(config, channels))
    });

    registry.register(
        "tls_fingerprint",
        "enable_tls_fingerprint",
        |config, channels| Box::new(TlsFingerprintDetector::new(config, channels)),
    );

    registry.register(
        "traffic_analyzer",
        "enable_traffic_analyzer",
        |config, channels| Box::new(TrafficAnalyzerDetector::new(config, channels)),
    );

    registry
}

/// Correlate signals into stable host/service assets. A signal with a local
/// `port` belongs to that service endpoint; passive signals without a local
/// port remain attached to the host-level asset.
fn correlate_signals(
    signals: Vec<Signal>,
    agents_by_asset: &mut HashMap<String, DetectedAgent>,
    on_agent: &Option<OnAgentCallback>,
) {
    let mut updated_assets = Vec::new();

    for signal in signals {
        let ip_str = signal
            .evidence
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if ip_str.is_empty() {
            continue;
        }
        let ip: IpAddr = ip_str.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let port = signal
            .evidence
            .get("port")
            .and_then(|value| value.as_u64())
            .and_then(|value| u16::try_from(value).ok());
        // These active service detectors all ride over TCP. Keeping the key at
        // the transport layer lets a port probe, HTTP probe, MCP probe, and
        // A2A probe for the same endpoint corroborate one another.
        let transport = if port.is_some() { "tcp" } else { "network" };
        let asset_id = crate::models::stable_asset_id(ip, port, transport);

        let prev_count = agents_by_asset
            .get(&asset_id)
            .map(|a| a.signal_count)
            .unwrap_or(0);

        let agent = agents_by_asset
            .entry(asset_id.clone())
            .or_insert_with(|| DetectedAgent::for_endpoint(ip_str.clone(), ip, port, transport));
        agent.add_signal(signal);

        if agent.signal_count > prev_count && !updated_assets.contains(&asset_id) {
            updated_assets.push(asset_id);
        }
    }

    if let Some(ref cb) = on_agent {
        for asset_id in updated_assets {
            if let Some(agent) = agents_by_asset.get(&asset_id) {
                cb(agent);
            }
        }
    }
}

/// Detectors `agentsniff probe` accepts: the active ones that send traffic to
/// a host and port. Passive detectors (DNS, traffic, SSE capture) observe the
/// local network instead and are not a single-target check.
pub const PROBE_DETECTORS: &[&str] = &[
    "port_scanner",
    "endpoint_prober",
    "mcp_detector",
    "a2a_detector",
    "agentpin_prober",
    "tls_fingerprint",
];

/// Probe one `ip:port` with the named active detectors and return that
/// endpoint's agent record. The record has no signals when nothing was found.
///
/// Touches only `ip:port`: no discovery, no other hosts or ports, no DNS,
/// storage or notifications. Callers cap the request rate with
/// `crate::ratelimit::set_rate`.
pub async fn run_probe(
    config: &ScanConfig,
    ip: IpAddr,
    port: u16,
    detector_names: &[String],
) -> anyhow::Result<DetectedAgent> {
    for name in detector_names {
        if !PROBE_DETECTORS.contains(&name.as_str()) {
            anyhow::bail!(
                "detector `{name}` cannot probe a single target; choose from: {}",
                PROBE_DETECTORS.join(", ")
            );
        }
    }
    let mut config = config.clone();
    config.probe_port = Some(port);
    for (name, enabled) in [
        ("port_scanner", &mut config.enable_port_scanner),
        ("endpoint_prober", &mut config.enable_endpoint_prober),
        ("mcp_detector", &mut config.enable_mcp_detector),
        ("a2a_detector", &mut config.enable_a2a_detector),
        ("agentpin_prober", &mut config.enable_agentpin_prober),
        ("tls_fingerprint", &mut config.enable_tls_fingerprint),
    ] {
        *enabled = detector_names.iter().any(|n| n == name);
    }
    config.enable_dns_monitor = false;
    config.enable_traffic_analyzer = false;
    config.enable_sse_detector = false;

    let mut detectors = build_registry().create_enabled(&config, None);
    let mut signals = Vec::new();
    for detector in &mut detectors {
        detector.setup().await?;
        let result = detector.scan(&[ip]).await;
        detector.teardown().await?;
        signals.extend(result?);
    }

    let mut agents_by_asset = HashMap::new();
    correlate_signals(signals, &mut agents_by_asset, &None);
    let asset_id = crate::models::stable_asset_id(ip, Some(port), "tcp");
    let mut agent = apply_fusion_rules(agents_by_asset.into_values().collect())
        .into_iter()
        .find(|agent| agent.id == asset_id)
        .unwrap_or_else(|| DetectedAgent::for_endpoint(ip.to_string(), ip, Some(port), "tcp"));
    agent.update_status();
    Ok(agent)
}

/// Run a full network scan.
///
/// Resolves targets, runs all enabled detectors concurrently, streams
/// agent updates as each detector completes, applies fusion rules at the
/// end, and returns the final scan result.
pub async fn run_scan(
    config: &ScanConfig,
    ebpf_channels: Option<Arc<EbpfChannels>>,
    cancel: Option<CancellationToken>,
    on_agent: Option<OnAgentCallback>,
) -> anyhow::Result<ScanResult> {
    let mut result = ScanResult::new();
    result.target_network = config.target_network.clone();

    // 1. Resolve targets
    let targets = resolve_targets(config)?;
    tracing::info!("Resolved {} target(s)", targets.len());

    // Check cancellation
    if let Some(ref token) = cancel {
        if token.is_cancelled() {
            result.completed_at = Some(Utc::now());
            result.cancelled = true;
            return Ok(result);
        }
    }

    // 2. Build registry and create enabled detectors
    let registry = build_registry();
    let mut detectors = registry.create_enabled(config, ebpf_channels);
    let detector_scope: Vec<DetectorType> = detectors
        .iter()
        .map(|detector| detector.detector_type())
        .collect();
    result.scope_id = scan_scope_id(config, &targets, &detector_scope);
    tracing::info!("Enabled {} detector(s)", detectors.len());

    // 3. Setup each detector (log errors, continue)
    for detector in &mut detectors {
        if let Err(e) = detector.setup().await {
            let msg = format!("Failed to setup detector '{}': {}", detector.name(), e);
            tracing::error!("{}", msg);
            result.errors.push(msg);
        }
    }

    // Check cancellation
    if let Some(ref token) = cancel {
        if token.is_cancelled() {
            result.completed_at = Some(Utc::now());
            result.cancelled = true;
            return Ok(result);
        }
    }

    // 4. Spawn all detectors into a JoinSet for incremental result processing
    let targets = Arc::new(targets);
    let mut join_set = JoinSet::new();

    for detector in detectors {
        let targets = Arc::clone(&targets);
        let detector_type = detector.detector_type();
        let detector: Arc<dyn Detector> = Arc::from(detector);

        join_set.spawn(async move { (detector_type, detector.scan(&targets).await) });
    }

    // 5. Process results incrementally as each detector completes
    let mut agents_by_asset: HashMap<String, DetectedAgent> = HashMap::new();

    while let Some(task_result) = join_set.join_next().await {
        // Check cancellation between detectors
        if let Some(ref token) = cancel {
            if token.is_cancelled() {
                result.completed_at = Some(Utc::now());
                result.cancelled = true;
                // Return whatever we have so far
                result.agents = agents_by_asset.into_values().collect();
                return Ok(result);
            }
        }

        match task_result {
            Ok((detector_type, Ok(signals))) => {
                result.detectors_run.push(detector_type);
                tracing::info!(
                    "Detector {:?} produced {} signal(s)",
                    detector_type,
                    signals.len()
                );
                // Incrementally correlate and stream to dashboard
                correlate_signals(signals, &mut agents_by_asset, &on_agent);
            }
            Ok((detector_type, Err(error))) => {
                result.detectors_run.push(detector_type);
                let message = format!("Detector {detector_type:?} failed: {error}");
                tracing::error!("{message}");
                result.errors.push(message);
            }
            Err(e) => {
                let msg = format!("Detector task panicked: {}", e);
                tracing::error!("{}", msg);
                result.errors.push(msg);
            }
        }
    }

    // 5b. Load Zeek supplementary signals (post-detector, pre-fusion)
    if config.zeek_enabled && !config.zeek_log_path.is_empty() {
        tracing::info!("Loading Zeek data from {}", config.zeek_log_path);
        let zeek = ZeekDataSource::new(&config.zeek_log_path);
        let time_window = std::time::Duration::from_secs(config.zeek_time_window);
        let sigs = crate::signatures::SignatureData::load_embedded();

        // Convert Zeek DNS records to signals
        match zeek.load_dns(&targets, time_window).await {
            Ok(dns_records) => {
                let mut infra_domains = sigs.agent_infra_domains.clone();
                infra_domains.extend(sigs.verified_mcp_remote_domains());

                let mut zeek_signals = Vec::new();
                for rec in &dns_records {
                    let query = rec.query.trim_end_matches('.');
                    let category = crate::detectors::dns_monitor::matches_known_domain(
                        query,
                        &sigs.llm_domains,
                        &infra_domains,
                        &sigs.domain_suffixes,
                    );
                    if category == Some("llm_api") {
                        zeek_signals.push(Signal::new(
                            DetectorType::Zeek,
                            "llm_api_domain_query".to_string(),
                            format!("Zeek: DNS query to LLM domain {}", query),
                            Confidence::High,
                            serde_json::json!({
                                "ip": rec.src_ip.to_string(),
                                "domain": rec.query,
                                "source": "zeek",
                            }),
                        ));
                    } else if category.is_some() {
                        zeek_signals.push(Signal::new(
                            DetectorType::Zeek,
                            "agent_infrastructure_domain_query".to_string(),
                            format!("Zeek: DNS query to agent infra domain {}", query),
                            Confidence::Medium,
                            serde_json::json!({
                                "ip": rec.src_ip.to_string(),
                                "domain": rec.query,
                                "source": "zeek",
                            }),
                        ));
                    }
                }

                if !zeek_signals.is_empty() {
                    tracing::info!(
                        "Zeek produced {} supplementary signal(s)",
                        zeek_signals.len()
                    );
                    result.detectors_run.push(DetectorType::Zeek);
                    correlate_signals(zeek_signals, &mut agents_by_asset, &on_agent);
                }
            }
            Err(error) => {
                let message = format!("Zeek DNS ingestion failed: {error}");
                tracing::warn!("{message}");
                result.errors.push(message);
            }
        }

        // Convert Zeek TLS records to signals (only matching fingerprints or LLM domains)
        match zeek.load_tls(&targets, time_window).await {
            Ok(tls_records) => {
                let mut zeek_tls_signals = Vec::new();
                for rec in &tls_records {
                    // Match by server_name against known LLM domains
                    let server_match = rec.server_name.as_deref().is_some_and(|sn| {
                        let sn = sn.trim_end_matches('.');
                        crate::detectors::dns_monitor::matches_known_domain(
                            sn,
                            &sigs.llm_domains,
                            &sigs.agent_infra_domains,
                            &sigs.domain_suffixes,
                        )
                        .is_some()
                    });

                    let fingerprint_match = rec.ja3_hash.as_deref().and_then(|hash| {
                        crate::detectors::tls_fingerprint::match_tls_fingerprint(
                            &sigs.tls_fingerprints,
                            hash,
                        )
                    });

                    if server_match || fingerprint_match.is_some() {
                        let confidence = if server_match {
                            Confidence::Medium
                        } else {
                            Confidence::Low
                        };
                        zeek_tls_signals.push(Signal::new(
                            DetectorType::Zeek,
                            "tls_fingerprint_captured".to_string(),
                            format!(
                                "Zeek: TLS to LLM domain {} (JA3: {})",
                                rec.server_name.as_deref().unwrap_or("unknown"),
                                rec.ja3_hash.as_deref().unwrap_or("none")
                            ),
                            confidence,
                            serde_json::json!({
                                "ip": rec.src_ip.to_string(),
                                "server_name": rec.server_name,
                                "ja3": rec.ja3_hash,
                                "fingerprint_profile": fingerprint_match,
                                "source": "zeek",
                            }),
                        ));
                    }
                }
                if !zeek_tls_signals.is_empty() {
                    correlate_signals(zeek_tls_signals, &mut agents_by_asset, &on_agent);
                }
            }
            Err(error) => {
                let message = format!("Zeek TLS ingestion failed: {error}");
                tracing::warn!("{message}");
                result.errors.push(message);
            }
        }
    }

    // 6. Apply fusion rules to the final set
    let agents: Vec<DetectedAgent> = agents_by_asset.into_values().collect();
    let mut agents = apply_fusion_rules(agents);

    // 6b. Service enrichment (post-fusion, pre-final-status)
    if config.enrich_enabled {
        tracing::info!("Running service enrichment");
        let enricher = ServiceEnricher::new(config.enrich_timeout);
        match enricher.enrich(agents.clone()).await {
            Ok(enriched) => {
                result.detectors_run.push(DetectorType::ServiceEnricher);
                agents = enriched;
            }
            Err(e) => {
                let msg = format!("Service enrichment failed: {}", e);
                tracing::warn!("{}", msg);
                result.errors.push(msg);
            }
        }
    }

    // 6c. Import the user's own Nmap XML results (never executes Nmap)
    if !config.nmap_xml_import.is_empty() {
        match read_nmap_xml(&config.nmap_xml_import) {
            Ok(xml) => {
                apply_nmap_xml(&mut agents, &xml);
                result.detectors_run.push(DetectorType::NmapEnricher);
            }
            Err(e) => {
                let msg = format!("Nmap XML import failed: {}", e);
                tracing::warn!("{}", msg);
                result.errors.push(msg);
            }
        }
    }

    // 7. Final status update and callback for agents that changed after fusion
    let mut final_agents = Vec::new();
    for mut agent in agents {
        agent.update_status();
        if let Some(ref cb) = on_agent {
            cb(&agent);
        }
        final_agents.push(agent);
    }

    result.agents = final_agents;
    result.completed_at = Some(Utc::now());

    Ok(result)
}

#[cfg(test)]
mod correlation_tests {
    use super::*;

    fn signal(port: u16, detector: DetectorType, signal_type: &str) -> Signal {
        Signal::new(
            detector,
            signal_type.to_string(),
            signal_type.to_string(),
            Confidence::High,
            serde_json::json!({"ip": "10.0.0.8", "port": port}),
        )
    }

    #[test]
    fn separates_services_on_the_same_host() {
        let mut assets = HashMap::new();
        correlate_signals(
            vec![
                signal(3000, DetectorType::PortScanner, "open_agent_port"),
                signal(8080, DetectorType::PortScanner, "open_agent_port"),
            ],
            &mut assets,
            &None,
        );

        assert_eq!(assets.len(), 2);
        assert!(assets.values().any(|agent| agent.port == Some(3000)));
        assert!(assets.values().any(|agent| agent.port == Some(8080)));
    }

    #[test]
    fn merges_detectors_for_the_same_service() {
        let mut assets = HashMap::new();
        correlate_signals(
            vec![
                signal(6274, DetectorType::PortScanner, "open_agent_port"),
                signal(6274, DetectorType::McpDetector, "mcp_server_confirmed"),
            ],
            &mut assets,
            &None,
        );

        assert_eq!(assets.len(), 1);
        let asset = assets.values().next().unwrap();
        assert_eq!(asset.port, Some(6274));
        assert_eq!(asset.signal_count, 2);
    }

    #[test]
    fn scan_scope_is_order_independent_and_detector_specific() {
        let config = ScanConfig::default();
        let first_targets = vec!["10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap()];
        let second_targets = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        let first_detectors = vec![DetectorType::McpDetector, DetectorType::PortScanner];
        let second_detectors = vec![DetectorType::PortScanner, DetectorType::McpDetector];

        let scope = scan_scope_id(&config, &first_targets, &first_detectors);
        assert_eq!(
            scope,
            scan_scope_id(&config, &second_targets, &second_detectors)
        );
        assert_ne!(
            scope,
            scan_scope_id(&config, &second_targets, &[DetectorType::PortScanner])
        );
    }
}
