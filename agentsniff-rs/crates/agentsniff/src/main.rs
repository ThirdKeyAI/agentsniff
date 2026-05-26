use std::fs;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use agentsniff::baseline::BaselineTracker;
use agentsniff::config::ScanConfig;
use agentsniff::ebpf::try_load_ebpf;
use agentsniff::models::ScanResult;
use agentsniff::notifier::send_alerts;
use agentsniff::sarif_export::to_sarif;
use agentsniff::scanner::run_scan;
use agentsniff::server::run_server;
use agentsniff::signatures::{SignatureData, VerificationStatus};
use agentsniff::storage::{SqliteBackend, StorageBackend};

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";
const ANSI_RED: &str = "\x1b[91m";
const ANSI_GREEN: &str = "\x1b[92m";
const ANSI_YELLOW: &str = "\x1b[93m";
const ANSI_BLUE: &str = "\x1b[94m";
const ANSI_CYAN: &str = "\x1b[96m";

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Csv,
    Sarif,
}

#[derive(Parser)]
#[command(name = "agentsniff", version, about = "AI Agent Network Scanner")]
enum Cli {
    /// Scan a network for AI agents
    Scan {
        /// Target network in CIDR notation (e.g., 192.168.1.0/24)
        #[arg(default_value = "192.168.1.0/24")]
        network: String,

        /// Comma-separated list of specific hosts to scan
        #[arg(long)]
        hosts: Option<String>,

        /// Comma-separated list of hosts to exclude
        #[arg(long)]
        exclude: Option<String>,

        /// Output format
        #[arg(long, short = 'f', value_enum, default_value = "table")]
        format: OutputFormat,

        /// Optional path to a YAML config file
        #[arg(long)]
        config: Option<String>,

        /// Write output to a file instead of stdout
        #[arg(long = "output", short = 'o', alias = "output-file")]
        output: Option<String>,

        /// Comma-separated list of detectors to enable (default: all)
        #[arg(long)]
        detectors: Option<String>,

        /// HTTP request timeout in seconds
        #[arg(long, default_value_t = 5.0)]
        timeout: f64,

        /// Maximum concurrent connections
        #[arg(long, default_value_t = 100)]
        concurrency: usize,

        /// Continuous scanning interval in seconds (0 = one-shot)
        #[arg(long, default_value_t = 0)]
        continuous: u64,

        /// Webhook URL for alert notifications (auto-enables alerting)
        #[arg(long = "webhook-url")]
        webhook_url: Option<String>,

        /// Comma-separated email recipients for alerts (auto-enables alerting)
        #[arg(long = "smtp-to")]
        smtp_to: Option<String>,

        /// SQLite database path for persistent history
        #[arg(long)]
        db: Option<String>,

        /// Log file path (default: no file logging)
        #[arg(long = "log-file")]
        log_file: Option<String>,

        /// Path to Zeek JSON log directory (enables Zeek integration)
        #[arg(long = "zeek-logs")]
        zeek_logs: Option<String>,

        /// Enable nmap enrichment of detected agents (requires nmap)
        #[arg(long)]
        nmap: bool,

        /// Arguments to pass to nmap
        #[arg(long = "nmap-args", default_value = "-sV")]
        nmap_args: String,

        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Suppress all non-error output
        #[arg(long, short = 'q', conflicts_with = "verbose")]
        quiet: bool,
    },
    /// Start the web dashboard server
    Serve {
        /// Port to listen on
        #[arg(long, default_value_t = 9090)]
        port: u16,

        /// Host address to bind to
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Default scan target network
        #[arg(long)]
        network: Option<String>,

        /// SQLite database path for persistent history
        #[arg(long)]
        db: Option<String>,

        /// Log file path (default: no file logging)
        #[arg(long = "log-file")]
        log_file: Option<String>,

        /// Optional path to a YAML config file
        #[arg(long)]
        config: Option<String>,

        /// Enable verbose output
        #[arg(long, short = 'v')]
        verbose: bool,
    },
    /// Update detection signatures from GitHub
    UpdateSignatures {
        /// Verify signatures after update
        #[arg(long, default_value = "true")]
        verify: bool,

        /// Skip signature verification (overrides --verify)
        #[arg(long = "no-verify")]
        no_verify: bool,

        /// Base URL for signature files
        #[arg(long)]
        url: Option<String>,
    },
    /// Generate a default configuration file
    InitConfig {
        /// Output file path
        #[arg(long, default_value = "agentsniff.yaml")]
        output: String,

        /// Overwrite existing file
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Scan {
            network,
            hosts,
            exclude,
            format,
            config,
            output,
            detectors,
            timeout,
            concurrency,
            continuous,
            webhook_url,
            smtp_to,
            db,
            log_file,
            zeek_logs,
            nmap,
            nmap_args,
            verbose,
            quiet,
        } => {
            // 1. Build config from YAML (or env) and apply CLI overrides.
            let mut scan_config = if let Some(path) = config {
                ScanConfig::from_yaml_file(&path)?
            } else {
                ScanConfig::default()
            };

            scan_config.target_network = network;
            scan_config.output_format = format_to_string(format);
            if let Some(o) = output {
                scan_config.output_file = o;
            }
            scan_config.verbose = verbose;
            scan_config.quiet = quiet;
            scan_config.http_timeout = timeout;
            scan_config.port_scan_concurrency = concurrency;
            scan_config.scan_interval = continuous;

            if let Some(lf) = log_file {
                scan_config.log_file = lf;
            }
            if let Some(d) = db {
                scan_config.storage.sqlite_path = d;
            }
            if let Some(h) = hosts {
                scan_config.target_hosts =
                    h.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(e) = exclude {
                scan_config.exclude_hosts =
                    e.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(w) = webhook_url {
                scan_config.webhook_url = w;
                scan_config.alert_enabled = true;
            }
            if let Some(s) = smtp_to {
                scan_config.smtp_to =
                    s.split(',').map(|x| x.trim().to_string()).collect();
                scan_config.alert_enabled = true;
            }
            if let Some(z) = zeek_logs {
                scan_config.zeek_enabled = true;
                scan_config.zeek_log_path = z;
            }
            if nmap {
                scan_config.nmap_enabled = true;
            }
            if nmap_args != "-sV" {
                scan_config.nmap_scan_args = nmap_args;
            }
            if let Some(d) = detectors {
                apply_detector_filter(&mut scan_config, &d);
            }
            let scan_config = ScanConfig::from_env_with_defaults(scan_config);

            // 2. Initialize logging now (after CLI parse + env-var overrides).
            init_logging(scan_config.verbose, scan_config.quiet, &scan_config.log_file)?;

            // 3. Banner + signature status (unless quiet).
            if !quiet {
                print_banner();
                print_signature_status();
            }

            // 4. Open storage and run.
            let storage: Arc<dyn StorageBackend> = Arc::new(
                SqliteBackend::new(&scan_config.storage.sqlite_path)
                    .map_err(|e| anyhow::anyhow!("failed to open storage: {e}"))?,
            );

            if scan_config.scan_interval > 0 {
                run_continuous_scans(&scan_config, format, storage).await?;
            } else {
                run_oneshot_scan(&scan_config, format, storage).await?;
            }
        }

        Cli::Serve {
            port,
            host,
            network,
            db,
            log_file,
            config,
            verbose,
        } => {
            let mut scan_config = if let Some(path) = config {
                ScanConfig::from_yaml_file(&path)?
            } else {
                ScanConfig::default()
            };

            scan_config.api_port = port;
            scan_config.api_host = host;
            if let Some(n) = network {
                scan_config.target_network = n;
            }
            if let Some(d) = db {
                scan_config.storage.sqlite_path = d;
            }
            if let Some(lf) = log_file {
                scan_config.log_file = lf;
            }
            scan_config.verbose = verbose;
            let scan_config = ScanConfig::from_env_with_defaults(scan_config);

            init_logging(verbose, false, &scan_config.log_file)?;
            tracing::info!(
                "Starting server on {}:{}",
                scan_config.api_host,
                scan_config.api_port
            );

            // Print startup info.
            let sigs = SignatureData::load_with_overlay();
            let verified = sigs
                .verification_status
                .values()
                .filter(|v| **v == VerificationStatus::Verified)
                .count();
            let total = sigs.verification_status.len();
            println!("agentsniff v{}", env!("CARGO_PKG_VERSION"));

            let (ebpf_status, ebpf_channels) =
                try_load_ebpf(&scan_config.ebpf_interface);
            ebpf_status.print_status();

            println!(
                "  Signatures:           {} verified ({}/{})",
                if verified == total { "\u{2713}" } else { "\u{2717}" },
                verified,
                total
            );

            run_server(scan_config, ebpf_channels).await?;
        }

        Cli::UpdateSignatures {
            verify,
            no_verify,
            url,
        } => {
            init_logging(false, false, "")?;
            let do_verify = verify && !no_verify;
            if !do_verify {
                println!("Warning: signature verification is disabled.");
            }
            agentsniff::signatures::updater::update_signatures(
                do_verify,
                url.as_deref(),
            )
            .await?;
        }

        Cli::InitConfig { output, force } => {
            init_logging(false, false, "")?;
            let path = std::path::Path::new(&output);
            if path.exists() && !force {
                eprintln!(
                    "Error: {} already exists. Use --force to overwrite.",
                    output
                );
                std::process::exit(1);
            }
            let yaml = agentsniff::config::default_config_yaml();
            fs::write(&output, yaml)?;
            println!("Generated default config: {}", output);
        }
    }

    Ok(())
}

fn format_to_string(format: OutputFormat) -> String {
    match format {
        OutputFormat::Table => "table",
        OutputFormat::Json => "json",
        OutputFormat::Csv => "csv",
        OutputFormat::Sarif => "sarif",
    }
    .to_string()
}

/// Toggle detector enable flags so only the named detectors are active.
fn apply_detector_filter(config: &mut ScanConfig, names: &str) {
    let enabled: std::collections::HashSet<&str> =
        names.split(',').map(|s| s.trim()).collect();
    config.enable_dns_monitor = enabled.contains("dns_monitor");
    config.enable_port_scanner = enabled.contains("port_scanner");
    config.enable_agentpin_prober = enabled.contains("agentpin_prober");
    config.enable_mcp_detector = enabled.contains("mcp_detector");
    config.enable_endpoint_prober = enabled.contains("endpoint_prober");
    config.enable_tls_fingerprint = enabled.contains("tls_fingerprint");
    config.enable_traffic_analyzer = enabled.contains("traffic_analyzer");
    config.enable_sse_detector = enabled.contains("sse_detector");
}

/// Initialise tracing-subscriber with the requested level + optional file output.
fn init_logging(verbose: bool, quiet: bool, log_file: &str) -> anyhow::Result<()> {
    let level = if verbose {
        "agentsniff=debug,info"
    } else if quiet {
        "agentsniff=warn,warn"
    } else {
        "agentsniff=info"
    };
    let make_filter = || {
        tracing_subscriber::EnvFilter::try_new(level)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("agentsniff=info"))
    };

    let console = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(make_filter())
        .boxed();

    let mut layers: Vec<
        Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>,
    > = vec![console];

    if !log_file.is_empty() {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
        let mutex = std::sync::Mutex::new(file);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(mutex)
            .with_filter(make_filter())
            .boxed();
        layers.push(file_layer);
    }

    let _ = tracing_subscriber::registry().with(layers).try_init();
    Ok(())
}

fn print_banner() {
    println!(
        "{}{}    ___                    __  _____       _ ________
   /   | ____ ____  ____  / /_/ ___/____  (_) __/ __/
  / /| |/ __ `/ _ \\/ __ \\/ __/\\__ \\/ __ \\/ / /_/ /_
 / ___ / /_/ /  __/ / / / /_ ___/ / / / / / __/ __/
/_/  |_\\__, /\\___/_/ /_/\\__//____/_/ /_/_/_/ /_/
      /____/{}{}  AI Agent Network Scanner v{}
  Detect AI agents on your network{}",
        ANSI_CYAN, ANSI_BOLD, ANSI_RESET, ANSI_DIM, env!("CARGO_PKG_VERSION"), ANSI_RESET,
    );
}

fn print_signature_status() {
    let sigs = SignatureData::load_with_overlay();
    let status = &sigs.verification_status;

    let invalid: Vec<&String> = status
        .iter()
        .filter(|(_, v)| **v == VerificationStatus::Invalid)
        .map(|(k, _)| k)
        .collect();
    let verified: Vec<&String> = status
        .iter()
        .filter(|(_, v)| **v == VerificationStatus::Verified)
        .map(|(k, _)| k)
        .collect();

    if !invalid.is_empty() {
        let names: Vec<String> = invalid.iter().map(|s| s.to_string()).collect();
        println!(
            "  \x1b[41m\x1b[97m WARNING {} Invalid signatures: {}{}",
            ANSI_RESET,
            names.join(", "),
            ANSI_RESET
        );
        println!(
            "  {}Detection signatures may have been tampered with!{}",
            ANSI_RED, ANSI_RESET
        );
        println!(
            "  {}Run 'agentsniff update-signatures' to restore.{}",
            ANSI_DIM, ANSI_RESET
        );
        println!();
    } else if !verified.is_empty() {
        println!(
            "  {}Signatures verified ({}/{}){}",
            ANSI_GREEN,
            verified.len(),
            status.len(),
            ANSI_RESET
        );
        println!();
    }
}

async fn run_oneshot_scan(
    config: &ScanConfig,
    format: OutputFormat,
    storage: Arc<dyn StorageBackend>,
) -> anyhow::Result<()> {
    let result = run_scan(config, None, None, None).await?;
    output_result(&result, config, format)?;
    if let Err(e) = storage.save_scan(&result).await {
        tracing::warn!("Failed to persist scan: {}", e);
    }
    maybe_alert(&result, config).await;
    Ok(())
}

async fn run_continuous_scans(
    config: &ScanConfig,
    format: OutputFormat,
    storage: Arc<dyn StorageBackend>,
) -> anyhow::Result<()> {
    let cancel = CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            cancel.cancel();
        });
    }

    let mut baseline = BaselineTracker::new();
    let mut scan_num: u64 = 0;

    loop {
        scan_num += 1;
        tracing::info!("Starting scan #{}", scan_num);

        let result = tokio::select! {
            r = run_scan(config, None, Some(cancel.clone()), None) => r?,
            _ = cancel.cancelled() => {
                println!("\n{}Scan stopped by user{}", ANSI_YELLOW, ANSI_RESET);
                return Ok(());
            }
        };

        let anomalies = baseline.process(&result);
        if !anomalies.is_empty() {
            tracing::info!("Baseline: {} anomaly(ies) detected", anomalies.len());
        }

        output_result(&result, config, format)?;
        if let Err(e) = storage.save_scan(&result).await {
            tracing::warn!("Failed to persist scan: {}", e);
        }
        maybe_alert(&result, config).await;

        tracing::info!("Next scan in {}s...", config.scan_interval);
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(config.scan_interval)) => {}
            _ = cancel.cancelled() => {
                println!("\n{}Scan stopped by user{}", ANSI_YELLOW, ANSI_RESET);
                return Ok(());
            }
        }
    }
}

async fn maybe_alert(result: &ScanResult, config: &ScanConfig) {
    if !config.alert_enabled {
        return;
    }
    if config.webhook_url.is_empty() && config.smtp_to.is_empty() {
        return;
    }

    let qualifying: usize = result
        .agents
        .iter()
        .filter(|a| a.confidence_score >= config.alert_min_confidence)
        .count();
    if qualifying < config.alert_min_agents {
        return;
    }

    let outcomes = send_alerts(result, config).await;
    for outcome in outcomes {
        tracing::info!("Alert: {}", outcome);
    }
}

fn output_result(
    result: &ScanResult,
    config: &ScanConfig,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string_pretty(result)?,
        OutputFormat::Sarif => serde_json::to_string_pretty(&to_sarif(result))?,
        OutputFormat::Csv => render_csv(result),
        OutputFormat::Table => render_table(result, config.quiet),
    };

    if !config.output_file.is_empty() {
        fs::write(&config.output_file, format!("{}\n", rendered))?;
        if !config.quiet {
            println!(
                "{}Results saved to {}{}",
                ANSI_GREEN, config.output_file, ANSI_RESET
            );
        }
    } else if !config.quiet
        || matches!(format, OutputFormat::Json | OutputFormat::Csv | OutputFormat::Sarif)
    {
        println!("{}", rendered);
    }
    Ok(())
}

fn render_csv(result: &ScanResult) -> String {
    let mut out = String::from(
        "host,ip_address,port,agent_type,framework,confidence_score,confidence_level,status,signal_count,first_seen,last_seen\n",
    );
    for agent in &result.agents {
        let port_str = agent.port.map(|p| p.to_string()).unwrap_or_default();
        let agent_type = agent.agent_type.as_deref().unwrap_or("unknown");
        let framework = agent.framework.as_deref().unwrap_or("unknown");
        let status_str = format!("{:?}", agent.status).to_lowercase();
        let first_seen = agent
            .signals
            .first()
            .map(|s| s.timestamp.to_rfc3339())
            .unwrap_or_else(|| result.started_at.to_rfc3339());
        let last_seen = agent
            .signals
            .last()
            .map(|s| s.timestamp.to_rfc3339())
            .unwrap_or_else(|| result.started_at.to_rfc3339());

        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{}\n",
            agent.host,
            agent.ip_address,
            port_str,
            agent_type,
            framework,
            agent.confidence_score,
            agent.confidence_level,
            status_str,
            agent.signal_count,
            first_seen,
            last_seen,
        ));
    }
    out.trim_end_matches('\n').to_string()
}

fn confidence_color(level: &str) -> &'static str {
    match level {
        "confirmed" => ANSI_GREEN,
        "high" => ANSI_YELLOW,
        "medium" => ANSI_BLUE,
        _ => ANSI_DIM,
    }
}

fn status_icon(status: &str) -> &'static str {
    match status {
        "verified" => "\u{2713}",
        "detected" => "\u{25c9}",
        "suspected" => "\u{25ce}",
        _ => "\u{25cb}",
    }
}

fn render_table(result: &ScanResult, quiet: bool) -> String {
    let mut out = String::new();
    let agents = &result.agents;
    let duration = result
        .duration_seconds()
        .map(|d| format!("{:.1}s", d))
        .unwrap_or_else(|| "?".to_string());

    if !quiet {
        out.push_str(&format!("\n{}{}{}\n", ANSI_BOLD, "═".repeat(78), ANSI_RESET));
        out.push_str(&format!(
            "{}  SCAN RESULTS  {}{}│  ID: {}  │  Duration: {}  │  Detectors: {}{}\n",
            ANSI_BOLD,
            ANSI_RESET,
            ANSI_DIM,
            &result.scan_id.get(..8).unwrap_or(&result.scan_id),
            duration,
            result.detectors_run.len(),
            ANSI_RESET,
        ));
        out.push_str(&format!("{}{}{}\n", ANSI_BOLD, "═".repeat(78), ANSI_RESET));
    }

    if agents.is_empty() {
        out.push_str(&format!(
            "\n  {}No AI agents detected on {}{}\n",
            ANSI_DIM, result.target_network, ANSI_RESET
        ));
        return out;
    }

    // Summary line by confidence level.
    let mut by_conf: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for a in agents {
        *by_conf.entry(a.confidence_level.as_str()).or_insert(0) += 1;
    }
    out.push_str(&format!(
        "\n  {}{} agent(s) detected{}",
        ANSI_BOLD,
        agents.len(),
        ANSI_RESET
    ));
    for (level, count) in &by_conf {
        let c = confidence_color(level);
        out.push_str(&format!(" {}{} {}: {}{}", c, "\u{25a0}", level, count, ANSI_RESET));
    }
    out.push('\n');

    // Table header
    out.push_str(&format!(
        "\n  {:<20} {:<7} {:<18} {:<14} {:<14} {:<8} {}\n",
        "Host", "Port", "Type", "Framework", "Confidence", "Signals", "Status"
    ));
    out.push_str(&format!(
        "  {} {} {} {} {} {} {}\n",
        "─".repeat(20),
        "─".repeat(7),
        "─".repeat(18),
        "─".repeat(14),
        "─".repeat(14),
        "─".repeat(8),
        "─".repeat(10)
    ));

    for agent in agents {
        let level = agent.confidence_level.as_str();
        let color = confidence_color(level);
        let status_str = format!("{:?}", agent.status).to_lowercase();
        let icon = status_icon(&status_str);
        let conf_display = format!("{:.0}% ({})", agent.confidence_score * 100.0, level);
        let port_display = agent
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());

        out.push_str(&format!(
            "  {}{:<20}{} {:<7} {:<18} {:<14} {}{:<14}{} {:<8} {}{} {}{}\n",
            ANSI_BOLD,
            agent.ip_address.to_string(),
            ANSI_RESET,
            port_display,
            agent.agent_type.as_deref().unwrap_or("unknown"),
            agent.framework.as_deref().unwrap_or("unknown"),
            color,
            conf_display,
            ANSI_RESET,
            agent.signals.len(),
            color,
            icon,
            status_str,
            ANSI_RESET,
        ));
    }

    // Detail block
    out.push_str(&format!("\n{}{}{}\n", ANSI_BOLD, "─".repeat(78), ANSI_RESET));
    out.push_str(&format!("  {}DETECTION DETAILS{}\n", ANSI_BOLD, ANSI_RESET));
    out.push_str(&format!("{}\n", "─".repeat(78)));

    for agent in agents {
        let level = agent.confidence_level.as_str();
        let color = confidence_color(level);
        let port_suffix = agent
            .port
            .map(|p| format!(":{}", p))
            .unwrap_or_default();

        out.push_str(&format!(
            "\n  {}{}\u{25b8} {}{}{}  {}({}){}\n",
            color,
            ANSI_BOLD,
            agent.ip_address,
            port_suffix,
            ANSI_RESET,
            ANSI_DIM,
            agent.agent_type.as_deref().unwrap_or("unknown"),
            ANSI_RESET,
        ));

        if let Some(ref ap) = agent.agentpin_identity {
            let agent_id = ap.get("agent_id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let issuer = ap.get("issuer").and_then(|v| v.as_str()).unwrap_or("unknown");
            out.push_str(&format!(
                "    {}\u{26bf} AgentPin:{} {} (issuer: {})\n",
                ANSI_GREEN, ANSI_RESET, agent_id, issuer,
            ));
            if let Some(caps) = ap.get("capabilities").and_then(|v| v.as_array()) {
                let cap_strs: Vec<String> = caps
                    .iter()
                    .take(5)
                    .map(|c| c.as_str().unwrap_or("").to_string())
                    .collect();
                if !cap_strs.is_empty() {
                    out.push_str(&format!("      Capabilities: {}\n", cap_strs.join(", ")));
                }
            }
        }

        if let Some(ref mcp) = agent.mcp_capabilities {
            let si = mcp.get("server_info").cloned().unwrap_or_else(|| serde_json::json!({}));
            let name = si.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
            let version = si.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            out.push_str(&format!(
                "    {}\u{26a1} MCP Server:{} {} v{}\n",
                "\x1b[95m", ANSI_RESET, name, version,
            ));
        }

        for signal in agent.signals.iter().take(6) {
            let detector_name = format!("{:?}", signal.detector)
                .chars()
                .flat_map(|c| {
                    if c.is_uppercase() {
                        vec!['_', c.to_ascii_lowercase()]
                    } else {
                        vec![c]
                    }
                })
                .collect::<String>()
                .trim_start_matches('_')
                .to_string();
            let sig_level = format!("{:?}", signal.confidence).to_lowercase();
            let sig_color = confidence_color(&sig_level);
            out.push_str(&format!(
                "    {}\u{25cf} [{}]{} {}\n",
                sig_color, detector_name, ANSI_RESET, signal.description,
            ));
        }
        let remaining = agent.signals.len().saturating_sub(6);
        if remaining > 0 {
            out.push_str(&format!(
                "    {}... and {} more signal(s){}\n",
                ANSI_DIM, remaining, ANSI_RESET
            ));
        }
    }

    if !result.errors.is_empty() {
        out.push_str(&format!(
            "\n{}  \u{26a0} {} error(s) during scan:{}\n",
            ANSI_YELLOW,
            result.errors.len(),
            ANSI_RESET
        ));
        for err in result.errors.iter().take(5) {
            out.push_str(&format!("    {}\u{2022} {}{}\n", ANSI_DIM, err, ANSI_RESET));
        }
    }

    out.push_str(&format!("\n{}{}{}\n", ANSI_BOLD, "═".repeat(78), ANSI_RESET));
    out.trim_end_matches('\n').to_string()
}
