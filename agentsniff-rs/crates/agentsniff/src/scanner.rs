use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use chrono::Utc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::ScanConfig;
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
use crate::models::{DetectedAgent, ScanResult, Signal};

/// Callback type for reporting detected agents during a scan.
pub type OnAgentCallback = Box<dyn Fn(&DetectedAgent) + Send + Sync>;

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

    if prefix_len == 32 {
        return Ok(vec![IpAddr::V4(base_ip)]);
    }

    // Compute network mask and host count
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let network = u32::from(base_ip) & mask;
    let host_count = 1u32 << (32 - prefix_len);

    let mut addrs = Vec::new();

    if prefix_len >= 31 {
        // /31 point-to-point: include both addresses
        for i in 0..host_count {
            let ip = Ipv4Addr::from(network + i);
            addrs.push(IpAddr::V4(ip));
        }
    } else {
        // Skip network (first) and broadcast (last)
        for i in 1..(host_count - 1) {
            let ip = Ipv4Addr::from(network + i);
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

    Ok(targets)
}

/// Build a detector registry with all active detectors.
pub fn build_registry() -> DetectorRegistry {
    let mut registry = DetectorRegistry::new();

    registry.register("dns_monitor", "enable_dns_monitor", |config, channels| {
        Box::new(DnsMonitorDetector::new(config, channels))
    });

    registry.register("port_scanner", "enable_port_scanner", |config, _channels| {
        Box::new(PortScannerDetector::new(config))
    });

    registry.register("endpoint_prober", "enable_endpoint_prober", |config, _channels| {
        Box::new(EndpointProberDetector::new(config))
    });

    registry.register("mcp_detector", "enable_mcp_detector", |config, _channels| {
        Box::new(McpDetector::new(config))
    });

    registry.register("agentpin_prober", "enable_agentpin_prober", |config, _channels| {
        Box::new(AgentpinProber::new(config))
    });

    registry.register("sse_detector", "enable_sse_detector", |config, channels| {
        Box::new(SseDetector::new(config, channels))
    });

    registry.register("tls_fingerprint", "enable_tls_fingerprint", |config, channels| {
        Box::new(TlsFingerprintDetector::new(config, channels))
    });

    registry.register("traffic_analyzer", "enable_traffic_analyzer", |config, channels| {
        Box::new(TrafficAnalyzerDetector::new(config, channels))
    });

    registry
}

/// Correlate signals into agents by host IP, calling `on_agent` for each
/// new or updated agent.
fn correlate_signals(
    signals: Vec<Signal>,
    agents_by_host: &mut HashMap<String, DetectedAgent>,
    on_agent: &Option<OnAgentCallback>,
) {
    // Track which hosts got new signals so we can notify
    let mut updated_hosts = Vec::new();

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

        let prev_count = agents_by_host
            .get(&ip_str)
            .map(|a| a.signal_count)
            .unwrap_or(0);

        let agent = agents_by_host.entry(ip_str.clone()).or_insert_with(|| {
            let ip: IpAddr = ip_str
                .parse()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            DetectedAgent::new(ip_str.clone(), ip)
        });
        agent.add_signal(signal);

        // Only notify if the agent actually gained new signals
        if agent.signal_count > prev_count && !updated_hosts.contains(&ip_str) {
            updated_hosts.push(ip_str);
        }
    }

    // Notify for each updated agent
    if let Some(ref cb) = on_agent {
        for host in updated_hosts {
            if let Some(agent) = agents_by_host.get(&host) {
                cb(agent);
            }
        }
    }
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
            return Ok(result);
        }
    }

    // 2. Build registry and create enabled detectors
    let registry = build_registry();
    let mut detectors = registry.create_enabled(config, ebpf_channels);
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

        join_set.spawn(async move {
            let signals = match detector.scan(&targets).await {
                Ok(signals) => {
                    tracing::info!(
                        "Detector {:?} produced {} signal(s)",
                        detector_type,
                        signals.len()
                    );
                    signals
                }
                Err(e) => {
                    tracing::error!("Detector {:?} failed: {}", detector_type, e);
                    Vec::new()
                }
            };
            (detector_type, signals)
        });
    }

    // 5. Process results incrementally as each detector completes
    let mut agents_by_host: HashMap<String, DetectedAgent> = HashMap::new();

    while let Some(task_result) = join_set.join_next().await {
        // Check cancellation between detectors
        if let Some(ref token) = cancel {
            if token.is_cancelled() {
                result.completed_at = Some(Utc::now());
                // Return whatever we have so far
                result.agents = agents_by_host.into_values().collect();
                return Ok(result);
            }
        }

        match task_result {
            Ok((detector_type, signals)) => {
                result.detectors_run.push(detector_type);
                // Incrementally correlate and stream to dashboard
                correlate_signals(signals, &mut agents_by_host, &on_agent);
            }
            Err(e) => {
                let msg = format!("Detector task panicked: {}", e);
                tracing::error!("{}", msg);
                result.errors.push(msg);
            }
        }
    }

    // 6. Apply fusion rules to the final set
    let agents: Vec<DetectedAgent> = agents_by_host.into_values().collect();
    let agents = apply_fusion_rules(agents);

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
