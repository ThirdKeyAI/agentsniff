use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Storage backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub backend: String,
    pub sqlite_path: String,
    pub postgres_url: String,
    pub redis_url: String,
    pub redis_channel: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: "sqlite".to_string(),
            sqlite_path: "~/.agentsniff/agentsniff.db".to_string(),
            postgres_url: String::new(),
            redis_url: String::new(),
            redis_channel: "agentsniff:events:v1".to_string(),
        }
    }
}

/// Top-level scan configuration with sane defaults.
///
/// Can be loaded from a YAML file and/or overridden with environment variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    // ── Network targets ──────────────────────────────────────────────
    pub target_network: String,
    pub target_hosts: Vec<String>,
    pub exclude_hosts: Vec<String>,

    // ── Detector toggles ─────────────────────────────────────────────
    pub enable_dns_monitor: bool,
    pub enable_port_scanner: bool,
    pub enable_agentpin_prober: bool,
    pub enable_a2a_detector: bool,
    pub enable_mcp_detector: bool,
    pub enable_endpoint_prober: bool,
    pub enable_tls_fingerprint: bool,
    pub enable_traffic_analyzer: bool,
    pub enable_sse_detector: bool,

    // ── Scan parameters ──────────────────────────────────────────────
    pub port_scan_timeout: f64,
    pub port_scan_concurrency: usize,
    pub http_timeout: f64,
    pub http_concurrency: usize,
    pub dns_monitor_duration: u64,
    pub dns_interface: String,
    pub scan_interval: u64,

    // ── Output ───────────────────────────────────────────────────────
    pub output_format: String,
    pub output_file: String,
    pub verbose: bool,
    pub quiet: bool,

    // ── Logging ──────────────────────────────────────────────────────
    /// Optional file path for logs (empty = no file logging).
    pub log_file: String,

    // ── API server ───────────────────────────────────────────────────
    pub api_enabled: bool,
    pub api_host: String,
    pub api_port: u16,
    /// Shared secret for Basic/Bearer API authentication. Prefer the
    /// `AGENTSNIFF_API_TOKEN` environment variable over storing it in YAML.
    pub api_token: String,
    pub api_cors_origins: Vec<String>,

    // ── AgentPin verifier ────────────────────────────────────────────
    /// Operator-supplied trust bundle. Empty keeps the REST/MCP verifier disabled.
    pub agentpin_trust_bundle_path: String,
    /// Durable TOFU key-pin store used by the REST/MCP verifier.
    pub agentpin_pin_store_path: String,
    /// Audience that presented credentials must name.
    pub agentpin_expected_audience: String,

    // ── Storage ──────────────────────────────────────────────────────
    pub storage: StorageConfig,

    // ── Custom signatures ────────────────────────────────────────────
    pub custom_llm_domains: Vec<String>,
    pub custom_agent_infra_domains: Vec<String>,
    pub custom_agent_ports: HashMap<u16, String>,
    pub custom_framework_signatures: serde_json::Value,
    /// Out-of-band trusted ES256 public keys for A2A Agent Card signatures,
    /// keyed by the JWS `kid`. Self-advertised keys are never trusted.
    pub a2a_trusted_keys: HashMap<String, String>,

    // ── Alerting ─────────────────────────────────────────────────────
    pub alert_enabled: bool,
    /// Notify only for new, changed, or removed assets. Disable to retain the
    /// legacy behavior of alerting on every qualifying observation.
    pub alert_changes_only: bool,
    pub alert_min_agents: usize,
    pub alert_min_confidence: f64,
    pub alert_cooldown: u64,
    pub webhook_url: String,
    pub webhook_headers: HashMap<String, String>,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub smtp_use_tls: bool,
    pub smtp_from: String,
    pub smtp_to: Vec<String>,

    // ── eBPF ─────────────────────────────────────────────────────────
    pub ebpf_interface: String,

    // ── Integrations ────────────────────────────────────────────────
    pub zeek_enabled: bool,
    pub zeek_log_path: String,
    pub zeek_time_window: u64,
    /// Run naabu/httpx/zgrab2 against detected agents.
    pub enrich_enabled: bool,
    /// Per-tool timeout for enrichment, in seconds.
    pub enrich_timeout: u64,
    /// Path to the user's own Nmap XML results to import (never runs Nmap).
    pub nmap_xml_import: String,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            // Network targets
            target_network: "192.168.1.0/24".to_string(),
            target_hosts: Vec::new(),
            exclude_hosts: Vec::new(),

            // Detector toggles
            enable_dns_monitor: true,
            enable_port_scanner: true,
            enable_agentpin_prober: true,
            enable_a2a_detector: true,
            enable_mcp_detector: true,
            enable_endpoint_prober: true,
            enable_tls_fingerprint: true,
            enable_traffic_analyzer: true,
            enable_sse_detector: true,

            // Scan parameters
            port_scan_timeout: 2.0,
            port_scan_concurrency: 100,
            http_timeout: 5.0,
            http_concurrency: 100,
            dns_monitor_duration: 60,
            dns_interface: String::new(),
            scan_interval: 0,

            // Output
            output_format: "table".to_string(),
            output_file: String::new(),
            verbose: false,
            quiet: false,

            // Logging
            log_file: String::new(),

            // API server
            api_enabled: true,
            api_host: "127.0.0.1".to_string(),
            api_port: 9090,
            api_token: String::new(),
            api_cors_origins: vec!["*".to_string()],

            // AgentPin verifier
            agentpin_trust_bundle_path: String::new(),
            agentpin_pin_store_path: "~/.agentsniff/agentpin-pins.json".to_string(),
            agentpin_expected_audience: String::new(),

            // Storage
            storage: StorageConfig::default(),

            // Custom signatures
            custom_llm_domains: Vec::new(),
            custom_agent_infra_domains: Vec::new(),
            custom_agent_ports: HashMap::new(),
            custom_framework_signatures: serde_json::json!({}),
            a2a_trusted_keys: HashMap::new(),

            // Alerting
            alert_enabled: false,
            alert_changes_only: true,
            alert_min_agents: 1,
            alert_min_confidence: 0.5,
            alert_cooldown: 300,
            webhook_url: String::new(),
            webhook_headers: HashMap::new(),
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_user: String::new(),
            smtp_password: String::new(),
            smtp_use_tls: true,
            smtp_from: String::new(),
            smtp_to: Vec::new(),

            // eBPF
            ebpf_interface: String::new(),

            // Integrations
            zeek_enabled: false,
            zeek_log_path: String::new(),
            zeek_time_window: 300,
            enrich_enabled: false,
            enrich_timeout: 300,
            nmap_xml_import: String::new(),
        }
    }
}

impl ScanConfig {
    /// Change the webhook destination without carrying credentials across
    /// trust boundaries. Returns true when retained headers were cleared.
    pub fn set_webhook_destination(&mut self, url: String) -> bool {
        let changed = self.webhook_url != url;
        let cleared = changed && !self.webhook_headers.is_empty();
        if changed {
            self.webhook_headers.clear();
        }
        self.webhook_url = url;
        cleared
    }

    /// Load configuration from a YAML file on disk.
    pub fn from_yaml_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let value: serde_yaml::Value = serde_yaml::from_str(&contents)?;
        check_removed_nmap_keys(&value)?;
        let config: Self = serde_yaml::from_value(value)?;
        Ok(config)
    }

    /// Map a textual confidence level ("low" | "medium" | "high" | "confirmed")
    /// to a numeric threshold compatible with `alert_min_confidence`.
    ///
    /// Mirrors the dashboard / Python implementation's mapping so YAML or CLI
    /// callers can supply either a number or a level name.
    pub fn confidence_level_to_score(level: &str) -> f64 {
        match level.trim().to_ascii_lowercase().as_str() {
            "confirmed" => 0.9,
            "high" => 0.7,
            "medium" => 0.4,
            "low" => 0.1,
            _ => 0.1,
        }
    }

    /// Apply environment-variable overrides on top of an existing config.
    pub fn from_env_with_defaults(mut config: Self) -> Self {
        if let Ok(v) = std::env::var("AGENTSNIFF_TARGET_NETWORK") {
            config.target_network = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_API_PORT") {
            if let Ok(port) = v.parse::<u16>() {
                config.api_port = port;
            }
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_API_HOST") {
            config.api_host = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_API_TOKEN") {
            config.api_token = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_AGENTPIN_TRUST_BUNDLE") {
            config.agentpin_trust_bundle_path = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_AGENTPIN_PIN_STORE") {
            config.agentpin_pin_store_path = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_AGENTPIN_AUDIENCE") {
            config.agentpin_expected_audience = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_STORAGE_BACKEND") {
            config.storage.backend = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_POSTGRES_URL") {
            config.storage.postgres_url = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_REDIS_URL") {
            config.storage.redis_url = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_REDIS_CHANNEL") {
            config.storage.redis_channel = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_VERBOSE") {
            config.verbose = v == "1" || v.eq_ignore_ascii_case("true");
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_ALERT_CHANGES_ONLY") {
            config.alert_changes_only = v == "1" || v.eq_ignore_ascii_case("true");
        }
        config
    }
}

/// Generate a well-commented default YAML configuration template.
/// Keys removed in 2.3.0 when live Nmap execution was dropped.
const REMOVED_NMAP_KEYS: &[&str] = &["nmap_enabled", "nmap_scan_args", "nmap_timeout"];

/// Refuse configs that ask for live Nmap (`nmap_enabled: true`); warn about
/// and ignore the other removed keys so configs that disabled Nmap still load.
pub fn check_removed_nmap_keys(value: &serde_yaml::Value) -> anyhow::Result<()> {
    if value.get("nmap_enabled").and_then(|v| v.as_bool()) == Some(true) {
        anyhow::bail!(
            "nmap_enabled was removed in 2.3.0: AgentSniff no longer runs Nmap. \
             Use enrich_enabled (naabu, httpx, zgrab2) or import your own results \
             with nmap_xml_import / --nmap-xml <file>."
        );
    }
    for key in REMOVED_NMAP_KEYS {
        if value.get(*key).is_some() {
            // Logging is not initialized yet when configs load.
            eprintln!("warning: config key `{key}` was removed in 2.3.0 and is ignored");
        }
    }
    Ok(())
}

pub fn default_config_yaml() -> String {
    r#"# AgentSniff v2 Configuration
# See https://agentsniff.org/docs/configuration for full reference.

# ── Network targets ──────────────────────────────────────────────────
target_network: "192.168.1.0/24"
# target_hosts:
#   - "10.0.0.5"
#   - "myhost.local"
# exclude_hosts:
#   - "192.168.1.1"

# ── Detector toggles ────────────────────────────────────────────────
enable_dns_monitor: true
enable_port_scanner: true
enable_agentpin_prober: true
enable_a2a_detector: true
enable_mcp_detector: true
enable_endpoint_prober: true
enable_tls_fingerprint: true
enable_traffic_analyzer: true
enable_sse_detector: true

# ── Scan parameters ─────────────────────────────────────────────────
port_scan_timeout: 2.0        # seconds per port
port_scan_concurrency: 100
http_timeout: 5.0             # seconds per HTTP request
http_concurrency: 100
dns_monitor_duration: 60      # seconds to monitor DNS
# scan_interval: 0            # 0 = one-shot, >0 = repeat every N seconds

# ── Output ──────────────────────────────────────────────────────────
# output_format: "table"      # table, json, csv, sarif
# output_file: ""

# ── API server ──────────────────────────────────────────────────────
# api_enabled: true
# api_host: "127.0.0.1"
# api_port: 9090
# api_token: ""               # required for non-loopback; prefer AGENTSNIFF_API_TOKEN
# api_cors_origins:
#   - "*"

# ── AgentPin credential verifier (REST + MCP) ───────────────────────
# Configure all three values to expose the verifier. The trust bundle must
# arrive through an authenticated out-of-band channel; callers cannot replace it.
# agentpin_trust_bundle_path: "/etc/agentsniff/agentpin-trust-bundle.json"
# agentpin_pin_store_path: "~/.agentsniff/agentpin-pins.json"
# agentpin_expected_audience: "verifier.example"

# ── Storage ─────────────────────────────────────────────────────────
# storage:
#   backend: "sqlite"
#   sqlite_path: "~/.agentsniff/agentsniff.db"
#   postgres_url: ""
#   redis_url: ""             # optional cross-instance SSE event bus
#   redis_channel: "agentsniff:events:v1"

# ── Custom signatures ───────────────────────────────────────────────
# custom_llm_domains:
#   - "my-llm-api.example.com"
# custom_agent_infra_domains:
#   - "my-vector-db.example.com"
# custom_agent_ports:
#   12345: "my-agent-service"
# a2a_trusted_keys:           # JWS kid -> trusted ES256 public-key PEM
#   "agent-key-2026": |-
#     -----BEGIN PUBLIC KEY-----
#     ...
#     -----END PUBLIC KEY-----

# ── eBPF ────────────────────────────────────────────────────────────
# ebpf_interface: "eth0"      # network interface for eBPF capture

# ── Integrations ────────────────────────────────────────────────────
# zeek_enabled: false
# zeek_log_path: "/opt/zeek/logs/current"
# zeek_time_window: 300       # seconds of history to load

# enrich_enabled: false      # naabu + httpx + zgrab2 against detected agents
# enrich_timeout: 300         # seconds per tool
# nmap_xml_import: ""         # your own `nmap -oX` results; AgentSniff never runs Nmap

# ── Alerting ────────────────────────────────────────────────────────
# alert_enabled: false
# alert_changes_only: true    # alert only on new, changed, or removed assets
# alert_min_agents: 1
# alert_min_confidence: 0.5
# alert_cooldown: 300         # seconds between alerts
# webhook_url: ""
# webhook_headers: {}
# smtp_host: ""
# smtp_port: 587
# smtp_use_tls: true
# smtp_from: ""
# smtp_to: []
"#
    .to_string()
}
