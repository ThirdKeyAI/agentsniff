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
    #[serde(skip)]
    #[doc(hidden)]
    pub evidence_budget: std::sync::Arc<crate::limits::EvidenceBudget>,
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

    /// Set only by `agentsniff probe`: every active detector touches this one
    /// port instead of its own port list. Never read from YAML.
    #[serde(skip)]
    pub probe_port: Option<u16>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            // Network targets
            evidence_budget: std::sync::Arc::default(),
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
            api_cors_origins: Vec::new(),

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
            probe_port: None,
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
        // Never expand merge keys or print source snippets (which can contain
        // credentials). Keep parser/alias budgets and duplicate-key rejection.
        let options = serde_saphyr::options! {
            strict_booleans: true,
            merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
            with_snippet: false,
        };
        // Preserve scalar types before converting to config: direct typed YAML
        // deserialization would accept quoted booleans/numbers as native values.
        // JSON's map-key deserializer still supports custom_agent_ports' u16 keys.
        let value: serde_json::Value = serde_saphyr::from_str_with_options(&contents, options)
            .map_err(|error| match error.location() {
                Some(location) => anyhow::anyhow!(
                    "invalid YAML configuration at line {}, column {}",
                    location.line(),
                    location.column()
                ),
                None => anyhow::anyhow!("invalid YAML configuration"),
            })?;
        check_removed_nmap_keys(&value)?;
        let config: Self = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid configuration value type; check booleans, numbers, lists, and quoted strings"))?;
        Ok(config)
    }

    /// The ports an active detector should touch: just `probe_port` when set,
    /// otherwise the detector's own list.
    pub fn ports_or(&self, defaults: &[u16]) -> Vec<u16> {
        match self.probe_port {
            Some(port) => vec![port],
            None => defaults.to_vec(),
        }
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
    pub fn from_env_with_defaults(config: Self) -> anyhow::Result<Self> {
        Self::apply_env(config, |name| std::env::var(name).ok())
    }

    fn apply_env(config: Self, lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut values = serde_json::to_value(&config).expect("serializable configuration");
        for (key, current) in values.as_object_mut().expect("configuration object") {
            if key == "storage" {
                for (key, current) in current.as_object_mut().expect("storage object") {
                    let name = match key.as_str() {
                        "backend" => "STORAGE_BACKEND",
                        "sqlite_path" => "DB_PATH",
                        _ => key,
                    };
                    if let Some(raw) = lookup(&format!("AGENTSNIFF_{}", name.to_ascii_uppercase()))
                    {
                        *current = serde_json::Value::String(raw);
                    }
                }
                continue;
            }
            let name = match key.as_str() {
                "agentpin_trust_bundle_path" => "AGENTPIN_TRUST_BUNDLE",
                "agentpin_pin_store_path" => "AGENTPIN_PIN_STORE",
                "agentpin_expected_audience" => "AGENTPIN_AUDIENCE",
                _ => key,
            };
            let name = format!("AGENTSNIFF_{}", name.to_ascii_uppercase());
            let Some(raw) = lookup(&name) else { continue };
            let parsed = match current {
                serde_json::Value::String(_) => Some(serde_json::Value::String(raw)),
                serde_json::Value::Bool(_) => match raw.to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => Some(serde_json::Value::Bool(true)),
                    "0" | "false" | "no" | "off" => Some(serde_json::Value::Bool(false)),
                    _ => None,
                },
                serde_json::Value::Array(_) => Some(serde_json::json!(raw
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>())),
                _ => serde_json::from_str(&raw).ok(),
            };
            if let Some(value) = parsed {
                *current = value;
            } else {
                anyhow::bail!("invalid value for {name}");
            }
        }
        let mut updated: Self = serde_json::from_value(values)
            .map_err(|_| anyhow::anyhow!("invalid environment configuration; refusing to start"))?;
        if updated.webhook_url != config.webhook_url
            && lookup("AGENTSNIFF_WEBHOOK_HEADERS").is_none()
        {
            updated.webhook_headers.clear();
        }
        if (updated.smtp_host != config.smtp_host
            || updated.smtp_port != config.smtp_port
            || updated.smtp_use_tls != config.smtp_use_tls)
            && lookup("AGENTSNIFF_SMTP_PASSWORD").is_none()
        {
            updated.smtp_user.clear();
            updated.smtp_password.clear();
        }
        Ok(updated)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.http_timeout.is_finite() && self.http_timeout > 0.0 && self.http_timeout <= 300.0,
            "http_timeout must be between 0 and 300 seconds"
        );
        anyhow::ensure!(
            self.port_scan_timeout.is_finite()
                && self.port_scan_timeout > 0.0
                && self.port_scan_timeout <= 300.0,
            "port_scan_timeout must be between 0 and 300 seconds"
        );
        anyhow::ensure!(
            (1..=1024).contains(&self.http_concurrency)
                && (1..=1024).contains(&self.port_scan_concurrency),
            "concurrency must be between 1 and 1024"
        );
        anyhow::ensure!(
            self.dns_monitor_duration <= 3600,
            "dns_monitor_duration cannot exceed 3600 seconds"
        );
        Ok(())
    }
}

#[cfg(test)]
mod environment_tests {
    use super::*;

    #[test]
    fn overrides_yaml_and_retains_unset_values() {
        let base = ScanConfig {
            target_network: "10.0.0.1/32".into(),
            http_timeout: 2.0,
            ..ScanConfig::default()
        };
        let values = HashMap::from([
            ("AGENTSNIFF_ENABLE_DNS_MONITOR", "false"),
            ("AGENTSNIFF_API_PORT", "9191"),
            ("AGENTSNIFF_HTTP_TIMEOUT", "3.5"),
            ("AGENTSNIFF_STORAGE_BACKEND", "postgres"),
            ("AGENTSNIFF_POSTGRES_URL", "postgres://example/test"),
            ("AGENTSNIFF_TARGET_HOSTS", "127.0.0.1, ::1"),
        ]);
        let config =
            ScanConfig::apply_env(base, |key| values.get(key).map(|v| v.to_string())).unwrap();
        assert!(!config.enable_dns_monitor);
        assert_eq!(config.api_port, 9191);
        assert_eq!(config.http_timeout, 3.5);
        assert_eq!(config.target_network, "10.0.0.1/32");
        assert_eq!(config.storage.backend, "postgres");
        assert_eq!(config.target_hosts, ["127.0.0.1", "::1"]);
    }

    #[test]
    fn invalid_environment_fails_closed_without_exposing_secrets() {
        for (name, raw) in [
            ("AGENTSNIFF_API_PORT", "not-a-number"),
            ("AGENTSNIFF_ENABLE_DNS_MONITOR", "maybe"),
            ("AGENTSNIFF_WEBHOOK_HEADERS", "{secret broken"),
        ] {
            let error = ScanConfig::apply_env(ScanConfig::default(), |key| {
                (key == name).then(|| raw.into())
            })
            .unwrap_err();
            assert!(!error.to_string().contains(raw));
        }
    }

    #[test]
    fn destination_environment_changes_clear_retained_credentials() {
        let base = ScanConfig {
            webhook_url: "https://old.example".into(),
            webhook_headers: HashMap::from([("Authorization".into(), "secret".into())]),
            smtp_host: "old.example".into(),
            smtp_user: "user".into(),
            smtp_password: "secret".into(),
            ..ScanConfig::default()
        };
        let config = ScanConfig::apply_env(base, |key| match key {
            "AGENTSNIFF_WEBHOOK_URL" => Some("https://new.example".into()),
            "AGENTSNIFF_SMTP_HOST" => Some("new.example".into()),
            _ => None,
        })
        .unwrap();
        assert!(config.webhook_headers.is_empty());
        assert!(config.smtp_password.is_empty());
        assert!(config.smtp_user.is_empty());
    }
}

/// Generate a well-commented default YAML configuration template.
/// Keys removed in 2.3.0 when live Nmap execution was dropped.
const REMOVED_NMAP_KEYS: &[&str] = &["nmap_enabled", "nmap_scan_args", "nmap_timeout"];

/// Refuse live Nmap requests; warn about other removed settings.
pub fn check_removed_nmap_keys(value: &serde_json::Value) -> anyhow::Result<()> {
    if value.get("nmap_enabled").and_then(|value| value.as_bool()) == Some(true) {
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
# Cross-origin management requests are not supported.

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
