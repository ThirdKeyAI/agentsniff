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
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: "sqlite".to_string(),
            sqlite_path: "~/.agentsniff/agentsniff.db".to_string(),
            postgres_url: String::new(),
            redis_url: String::new(),
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

    // ── API server ───────────────────────────────────────────────────
    pub api_enabled: bool,
    pub api_host: String,
    pub api_port: u16,
    pub api_cors_origins: Vec<String>,

    // ── Storage ──────────────────────────────────────────────────────
    pub storage: StorageConfig,

    // ── Custom signatures ────────────────────────────────────────────
    pub custom_llm_domains: Vec<String>,
    pub custom_agent_infra_domains: Vec<String>,
    pub custom_agent_ports: HashMap<u16, String>,
    pub custom_framework_signatures: serde_json::Value,

    // ── Alerting ─────────────────────────────────────────────────────
    pub alert_enabled: bool,
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
    pub nmap_enabled: bool,
    pub nmap_scan_args: String,
    pub nmap_timeout: u64,
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

            // API server
            api_enabled: true,
            api_host: "0.0.0.0".to_string(),
            api_port: 9090,
            api_cors_origins: vec!["*".to_string()],

            // Storage
            storage: StorageConfig::default(),

            // Custom signatures
            custom_llm_domains: Vec::new(),
            custom_agent_infra_domains: Vec::new(),
            custom_agent_ports: HashMap::new(),
            custom_framework_signatures: serde_json::json!({}),

            // Alerting
            alert_enabled: false,
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
            nmap_enabled: false,
            nmap_scan_args: "-sV".to_string(),
            nmap_timeout: 120,
        }
    }
}

impl ScanConfig {
    /// Load configuration from a YAML file on disk.
    pub fn from_yaml_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&contents)?;
        Ok(config)
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
        if let Ok(v) = std::env::var("AGENTSNIFF_STORAGE_BACKEND") {
            config.storage.backend = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_POSTGRES_URL") {
            config.storage.postgres_url = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_REDIS_URL") {
            config.storage.redis_url = v;
        }
        if let Ok(v) = std::env::var("AGENTSNIFF_VERBOSE") {
            config.verbose = v == "1" || v.eq_ignore_ascii_case("true");
        }
        config
    }
}

/// Generate a well-commented default YAML configuration template.
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
# api_host: "0.0.0.0"
# api_port: 9090
# api_cors_origins:
#   - "*"

# ── Storage ─────────────────────────────────────────────────────────
# storage:
#   backend: "sqlite"
#   sqlite_path: "~/.agentsniff/agentsniff.db"
#   postgres_url: ""
#   redis_url: ""

# ── Custom signatures ───────────────────────────────────────────────
# custom_llm_domains:
#   - "my-llm-api.example.com"
# custom_agent_infra_domains:
#   - "my-vector-db.example.com"
# custom_agent_ports:
#   12345: "my-agent-service"

# ── eBPF ────────────────────────────────────────────────────────────
# ebpf_interface: "eth0"      # network interface for eBPF capture

# ── Integrations ────────────────────────────────────────────────────
# zeek_enabled: false
# zeek_log_path: "/opt/zeek/logs/current"
# zeek_time_window: 300       # seconds of history to load

# nmap_enabled: false
# nmap_scan_args: "-sV"
# nmap_timeout: 120           # seconds

# ── Alerting ────────────────────────────────────────────────────────
# alert_enabled: false
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
