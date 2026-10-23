use std::borrow::Cow;
use std::fs;
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use agentsniff::agentpin::{
    expand_user_path, load_agentpin_pins, load_agentpin_trust_bundle, read_bounded,
    read_bounded_path, save_agentpin_pins, verify_credential_from_bundle,
    AgentpinVerificationPolicy, MAX_AGENTPIN_CREDENTIAL_BYTES,
};
use agentsniff::baseline::apply_scan_diff;
use agentsniff::config::ScanConfig;
use agentsniff::ebpf::try_load_ebpf;
use agentsniff::models::ScanResult;
use agentsniff::notifier::Notifier;
use agentsniff::sarif_export::to_sarif;
use agentsniff::scanner::run_scan;
use agentsniff::server::run_server;
use agentsniff::signatures::{SignatureData, VerificationStatus};
use agentsniff::storage::{create_storage, StorageBackend};

/// Largest saved scan JSON accepted by `enrich`.
const MAX_SCAN_JSON_BYTES: usize = 256 * 1024 * 1024;

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
// Parsed once at startup; boxing the Scan variant buys nothing.
#[allow(clippy::large_enum_variant)]
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

        /// Enrich detected agents with naabu, httpx and zgrab2 (must be on PATH)
        #[arg(long)]
        enrich: bool,

        /// Import your own Nmap XML results (`nmap -oX`); AgentSniff never runs Nmap
        #[arg(long = "nmap-xml", value_name = "FILE")]
        nmap_xml: Option<String>,

        /// Removed in 2.3.0; fails with a pointer to --enrich and --nmap-xml
        #[arg(long, hide = true)]
        nmap: bool,

        /// Removed in 2.3.0; fails with a pointer to --enrich and --nmap-xml
        #[arg(long = "nmap-args", hide = true, allow_hyphen_values = true)]
        nmap_args: Option<String>,

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
        #[arg(long, default_value = "127.0.0.1")]
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
        /// Base URL for signature files
        #[arg(long)]
        url: Option<String>,
    },
    /// Verify a presented AgentPin credential against an out-of-band trust bundle
    VerifyAgentpin {
        /// Read the credential JWT from this file (default: standard input)
        #[arg(long, value_name = "PATH")]
        credential_file: Option<String>,

        /// AgentPin pre-shared trust bundle containing discovery and revocation documents
        #[arg(long, value_name = "PATH")]
        trust_bundle: String,

        /// Persistent TOFU pin store
        #[arg(
            long,
            value_name = "PATH",
            default_value = "~/.agentsniff/agentpin-pins.json"
        )]
        pin_store: String,

        /// Expected credential audience (omit only when audience is not enforced)
        #[arg(long)]
        audience: Option<String>,
    },
    /// Probe a single IP:PORT with named detectors and print its agent record as JSON
    ///
    /// Sends traffic only to that address and port: no discovery, no other
    /// ports or hosts, no DNS, no update checks. Exits non-zero only on a tool
    /// failure; a target that is not an agent prints a record with no signals.
    Probe {
        /// Target as IP:PORT (IPv6 as [ADDR]:PORT); hostnames are not accepted
        target: String,

        /// Comma-separated active detectors: port_scanner, endpoint_prober,
        /// mcp_detector, a2a_detector, agentpin_prober, tls_fingerprint
        #[arg(long, required = true)]
        detectors: String,

        /// Cap on requests and TCP connections per second, combined (e.g. 1 or 0.5)
        #[arg(long)]
        rate: Option<f64>,

        /// Per-request and per-connection timeout in seconds
        #[arg(long, default_value_t = 5.0)]
        timeout: f64,

        /// Upper bound on the whole probe in seconds; exceeding it is a failure
        #[arg(long = "max-time", default_value_t = 600.0)]
        max_time: f64,

        /// Optional YAML config (custom agent ports, trusted A2A keys)
        #[arg(long)]
        config: Option<String>,
    },
    /// Apply your own Nmap XML results to a saved JSON scan (never runs Nmap)
    Enrich {
        /// Scan result JSON from `agentsniff scan -f json`
        #[arg(long, value_name = "FILE")]
        input: String,

        /// Your own Nmap XML results (`nmap -oX`)
        #[arg(long = "nmap-xml", value_name = "FILE")]
        nmap_xml: String,

        /// Write output to a file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
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
            enrich,
            nmap_xml,
            nmap,
            nmap_args,
            verbose,
            quiet,
        } => {
            if nmap || nmap_args.is_some() {
                anyhow::bail!(
                    "--nmap and --nmap-args were removed in 2.3.0: AgentSniff no longer runs Nmap. \
                     Use --enrich (naabu, httpx, zgrab2) or import your own results with --nmap-xml <file>."
                );
            }
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
                scan_config.target_hosts = h.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(e) = exclude {
                scan_config.exclude_hosts = e.split(',').map(|s| s.trim().to_string()).collect();
            }
            if let Some(w) = webhook_url {
                scan_config.set_webhook_destination(w);
                scan_config.alert_enabled = true;
            }
            if let Some(s) = smtp_to {
                scan_config.smtp_to = s.split(',').map(|x| x.trim().to_string()).collect();
                scan_config.alert_enabled = true;
            }
            if let Some(z) = zeek_logs {
                scan_config.zeek_enabled = true;
                scan_config.zeek_log_path = z;
            }
            if enrich {
                scan_config.enrich_enabled = true;
            }
            if let Some(x) = nmap_xml {
                scan_config.nmap_xml_import = x;
            }
            if let Some(d) = detectors {
                apply_detector_filter(&mut scan_config, &d);
            }
            let scan_config = ScanConfig::from_env_with_defaults(scan_config);

            // 2. Initialize logging now (after CLI parse + env-var overrides).
            init_logging(
                scan_config.verbose,
                scan_config.quiet,
                &scan_config.log_file,
            )?;

            // 3. Banner + signature status (unless quiet).
            if !quiet {
                print_banner();
                print_signature_status();
            }

            // 4. Open storage and run.
            let storage: Arc<dyn StorageBackend> =
                Arc::from(create_storage(&scan_config.storage).await?);

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

            let (ebpf_status, ebpf_channels) = try_load_ebpf(&scan_config.ebpf_interface);
            ebpf_status.print_status();

            println!(
                "  Signatures:           {} verified ({}/{})",
                if verified == total {
                    "\u{2713}"
                } else {
                    "\u{2717}"
                },
                verified,
                total
            );

            run_server(scan_config, ebpf_channels).await?;
        }

        Cli::UpdateSignatures { url } => {
            init_logging(false, false, "")?;
            agentsniff::signatures::updater::update_signatures(url.as_deref()).await?;
        }

        Cli::VerifyAgentpin {
            credential_file,
            trust_bundle,
            pin_store,
            audience,
        } => {
            init_logging(false, true, "")?;
            let credential = read_credential(credential_file.as_deref())?;
            let bundle = load_agentpin_trust_bundle(Path::new(&trust_bundle))?;
            let pin_path = expand_user_path(&pin_store);
            let mut pins = load_agentpin_pins(&pin_path)?;
            let report = verify_credential_from_bundle(
                credential.trim(),
                &bundle,
                &mut pins,
                audience.as_deref(),
                &AgentpinVerificationPolicy::default(),
            );
            if report.valid {
                save_agentpin_pins(&pin_path, &pins)?;
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.valid {
                std::process::exit(2);
            }
        }

        Cli::Probe {
            target,
            detectors,
            rate,
            timeout,
            max_time,
            config,
        } => {
            init_logging(false, true, "")?;
            let addr: std::net::SocketAddr = target
                .parse()
                .map_err(|_| anyhow::anyhow!("target must be IP:PORT, got `{target}`"))?;
            if !(timeout.is_finite() && timeout > 0.0 && max_time.is_finite() && max_time > 0.0) {
                anyhow::bail!("--timeout and --max-time must be positive numbers of seconds");
            }
            if let Some(rate) = rate {
                agentsniff::ratelimit::set_rate(rate)?;
            }
            let mut scan_config = match config {
                Some(path) => ScanConfig::from_yaml_file(&path)?,
                None => ScanConfig::default(),
            };
            scan_config.http_timeout = timeout;
            scan_config.port_scan_timeout = timeout;
            let names: Vec<String> = detectors
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let agent = tokio::time::timeout(
                Duration::from_secs_f64(max_time),
                agentsniff::scanner::run_probe(&scan_config, addr.ip(), addr.port(), &names),
            )
            .await
            .map_err(|_| anyhow::anyhow!("probe exceeded --max-time of {max_time}s"))??;
            println!("{}", serde_json::to_string_pretty(&agent)?);
        }

        Cli::Enrich {
            input,
            nmap_xml,
            output,
        } => {
            init_logging(false, true, "")?;
            let bytes = read_bounded_path(Path::new(&input), MAX_SCAN_JSON_BYTES, "scan JSON")?;
            let mut result: ScanResult = serde_json::from_slice(&bytes)?;
            let xml = agentsniff::integrations::nmap::read_nmap_xml(&nmap_xml)?;
            agentsniff::integrations::nmap::apply_nmap_xml(&mut result.agents, &xml);
            for agent in &mut result.agents {
                agent.update_status();
            }
            let json = serde_json::to_string_pretty(&result)?;
            match output {
                Some(path) => fs::write(path, json)?,
                None => println!("{json}"),
            }
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

fn read_credential(path: Option<&str>) -> anyhow::Result<String> {
    let bytes = match path {
        Some(path) => read_bounded_path(
            Path::new(path),
            MAX_AGENTPIN_CREDENTIAL_BYTES,
            "AgentPin credential",
        )?,
        None => read_bounded(
            std::io::stdin().lock(),
            MAX_AGENTPIN_CREDENTIAL_BYTES,
            "AgentPin credential from standard input",
        )?,
    };
    let credential = String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("AgentPin credential must be UTF-8"))?;
    if credential.trim().is_empty() {
        anyhow::bail!("AgentPin credential is empty");
    }
    Ok(credential)
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
    let enabled: std::collections::HashSet<&str> = names.split(',').map(|s| s.trim()).collect();
    config.enable_dns_monitor = enabled.contains("dns_monitor");
    config.enable_port_scanner = enabled.contains("port_scanner");
    config.enable_agentpin_prober = enabled.contains("agentpin_prober");
    config.enable_a2a_detector = enabled.contains("a2a_detector");
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

    let mut layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> = vec![console];

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
        ANSI_CYAN,
        ANSI_BOLD,
        ANSI_RESET,
        ANSI_DIM,
        env!("CARGO_PKG_VERSION"),
        ANSI_RESET,
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
    let mut result = run_scan(config, None, None, None).await?;
    classify_scan(&mut result, storage.as_ref()).await;
    output_result(&result, config, format)?;
    if let Err(e) = storage.save_scan(&result).await {
        tracing::warn!("Failed to persist scan: {}", e);
    }
    let mut notifier = Notifier::new(config);
    notifier.check_and_notify(&result).await?;
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

    let mut notifier = Notifier::new(config);
    let mut scan_num: u64 = 0;

    loop {
        scan_num += 1;
        tracing::info!("Starting scan #{}", scan_num);

        let mut result = tokio::select! {
            r = run_scan(config, None, Some(cancel.clone()), None) => r?,
            _ = cancel.cancelled() => {
                println!("\n{}Scan stopped by user{}", ANSI_YELLOW, ANSI_RESET);
                return Ok(());
            }
        };

        classify_scan(&mut result, storage.as_ref()).await;

        output_result(&result, config, format)?;
        if let Err(e) = storage.save_scan(&result).await {
            tracing::warn!("Failed to persist scan: {}", e);
        }
        notifier.check_and_notify(&result).await?;

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

async fn classify_scan(result: &mut ScanResult, storage: &dyn StorageBackend) {
    let previous = match storage.get_latest_scan(&result.scope_id).await {
        Ok(previous) => previous,
        Err(error) => {
            tracing::warn!("Failed to load persisted scan baseline: {}", error);
            None
        }
    };
    apply_scan_diff(result, previous.as_ref());
}

fn output_result(
    result: &ScanResult,
    config: &ScanConfig,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let terminal_display = config.output_file.is_empty() && std::io::stdout().is_terminal();
    let rendered = match format {
        OutputFormat::Json => serde_json::to_string_pretty(result)?,
        OutputFormat::Sarif => serde_json::to_string_pretty(&to_sarif(result))?,
        OutputFormat::Csv => render_csv(result),
        OutputFormat::Table => render_table(result, config.quiet, terminal_display),
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
        || matches!(
            format,
            OutputFormat::Json | OutputFormat::Csv | OutputFormat::Sarif
        )
    {
        println!("{}", rendered);
    }
    Ok(())
}

fn render_csv(result: &ScanResult) -> String {
    let mut out = String::from(
        "host,ip_address,port,agent_type,framework,confidence_score,confidence_level,status,signal_count,first_seen,last_seen,transport,presence_status,identity_assurance,risk_level,change_status,fingerprint\n",
    );
    for agent in &result.agents {
        let port_str = agent.port.map(|p| p.to_string()).unwrap_or_default();
        let agent_type = agent.agent_type.as_deref().unwrap_or("unknown");
        let framework = agent.framework.as_deref().unwrap_or("unknown");
        let status_str = format!("{:?}", agent.status).to_lowercase();
        let presence_status = format!("{:?}", agent.presence_status).to_lowercase();
        let identity_assurance = format!("{:?}", agent.identity_assurance).to_lowercase();
        let risk_level = format!("{:?}", agent.risk_level).to_lowercase();
        let change_status = format!("{:?}", agent.change_status).to_lowercase();

        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            agent.host,
            agent.ip_address,
            port_str,
            agent_type,
            framework,
            agent.confidence_score,
            agent.confidence_level,
            status_str,
            agent.signal_count,
            agent.first_seen.to_rfc3339(),
            agent.last_seen.to_rfc3339(),
            agent.transport,
            presence_status,
            identity_assurance,
            risk_level,
            change_status,
            agent.fingerprint,
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

fn display_text(value: &str, escape_terminal_controls: bool) -> Cow<'_, str> {
    if !escape_terminal_controls {
        return Cow::Borrowed(value);
    }
    if !value.chars().any(is_unsafe_terminal_character) {
        return Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if is_unsafe_terminal_character(character) {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    Cow::Owned(escaped)
}

fn is_unsafe_terminal_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            // Unicode line/paragraph separators, bidi controls, zero-width
            // format controls, and interlinear annotation controls.
            '\u{00ad}'
                | '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
        )
}

fn render_table(result: &ScanResult, quiet: bool, escape_terminal_controls: bool) -> String {
    let mut out = String::new();
    let agents = &result.agents;
    let duration = result
        .duration_seconds()
        .map(|d| format!("{:.1}s", d))
        .unwrap_or_else(|| "?".to_string());

    if !quiet {
        out.push_str(&format!(
            "\n{}{}{}\n",
            ANSI_BOLD,
            "═".repeat(78),
            ANSI_RESET
        ));
        out.push_str(&format!(
            "{}  SCAN RESULTS  {}{}│  ID: {}  │  Duration: {}  │  Detectors: {}{}\n",
            ANSI_BOLD,
            ANSI_RESET,
            ANSI_DIM,
            display_text(
                result.scan_id.get(..8).unwrap_or(&result.scan_id),
                escape_terminal_controls,
            ),
            duration,
            result.detectors_run.len(),
            ANSI_RESET,
        ));
        out.push_str(&format!("{}{}{}\n", ANSI_BOLD, "═".repeat(78), ANSI_RESET));
    }

    out.push_str(&format!(
        "\n  Changes: {} new, {} changed, {} unchanged, {} removed\n",
        result.diff.new_assets.len(),
        result.diff.changed_assets.len(),
        result.diff.unchanged_assets.len(),
        result.diff.removed_assets.len(),
    ));

    if agents.is_empty() {
        out.push_str(&format!(
            "\n  {}No current AI-agent assets detected on {}{}\n",
            ANSI_DIM,
            display_text(&result.target_network, escape_terminal_controls),
            ANSI_RESET
        ));
        for removed in &result.diff.removed_assets {
            let endpoint = removed
                .port
                .map(|port| format!("{}:{port}", removed.ip_address))
                .unwrap_or_else(|| removed.ip_address.to_string());
            out.push_str(&format!(
                "  {}Removed: {}{}\n",
                ANSI_YELLOW,
                display_text(&endpoint, escape_terminal_controls),
                ANSI_RESET
            ));
        }
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
        out.push_str(&format!(
            " {}{} {}: {}{}",
            c,
            "\u{25a0}",
            display_text(level, escape_terminal_controls),
            count,
            ANSI_RESET
        ));
    }
    out.push('\n');
    // Table header
    out.push_str(&format!(
        "\n  {:<20} {:<7} {:<16} {:<14} {:<18} {:<18} {:<10} {}\n",
        "Host", "Port", "Type", "Framework", "Presence", "Identity", "Risk", "Change"
    ));
    out.push_str(&format!(
        "  {} {} {} {} {} {} {} {}\n",
        "─".repeat(20),
        "─".repeat(7),
        "─".repeat(16),
        "─".repeat(14),
        "─".repeat(18),
        "─".repeat(18),
        "─".repeat(10),
        "─".repeat(10),
    ));

    for agent in agents {
        let level = agent.confidence_level.as_str();
        let color = confidence_color(level);
        let presence = format!("{:?}", agent.presence_status).to_lowercase();
        let identity = format!("{:?}", agent.identity_assurance).to_lowercase();
        let risk = format!("{:?}", agent.risk_level).to_lowercase();
        let change = format!("{:?}", agent.change_status).to_lowercase();
        let icon = status_icon(&format!("{:?}", agent.status).to_lowercase());
        let conf_display = format!(
            "{} {:.0}% {}",
            icon,
            agent.confidence_score * 100.0,
            presence,
        );
        let port_display = agent
            .port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string());

        out.push_str(&format!(
            "  {}{:<20}{} {:<7} {:<16} {:<14} {}{:<18}{} {:<18} {:<10} {}\n",
            ANSI_BOLD,
            agent.ip_address.to_string(),
            ANSI_RESET,
            port_display,
            display_text(
                agent.agent_type.as_deref().unwrap_or("unknown"),
                escape_terminal_controls,
            ),
            display_text(
                agent.framework.as_deref().unwrap_or("unknown"),
                escape_terminal_controls,
            ),
            color,
            conf_display,
            ANSI_RESET,
            display_text(&identity, escape_terminal_controls),
            display_text(&risk, escape_terminal_controls),
            display_text(&change, escape_terminal_controls),
        ));
    }

    // Detail block
    out.push_str(&format!(
        "\n{}{}{}\n",
        ANSI_BOLD,
        "─".repeat(78),
        ANSI_RESET
    ));
    out.push_str(&format!("  {}DETECTION DETAILS{}\n", ANSI_BOLD, ANSI_RESET));
    out.push_str(&format!("{}\n", "─".repeat(78)));

    for agent in agents {
        let level = agent.confidence_level.as_str();
        let color = confidence_color(level);
        let port_suffix = agent.port.map(|p| format!(":{}", p)).unwrap_or_default();

        out.push_str(&format!(
            "\n  {}{}\u{25b8} {}{}{}  {}({}){}\n",
            color,
            ANSI_BOLD,
            agent.ip_address,
            port_suffix,
            ANSI_RESET,
            ANSI_DIM,
            display_text(
                agent.agent_type.as_deref().unwrap_or("unknown"),
                escape_terminal_controls,
            ),
            ANSI_RESET,
        ));

        if let Some(ref ap) = agent.agentpin_identity {
            let agent_id = ap
                .get("agent_id")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    ap.get("agent_ids")
                        .and_then(|v| v.as_array())
                        .and_then(|ids| ids.first())
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("unknown");
            let entity = ap
                .get("entity")
                .or_else(|| ap.get("issuer"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            out.push_str(&format!(
                "    {}\u{26bf} AgentPin:{} {} (entity: {})\n",
                ANSI_GREEN,
                ANSI_RESET,
                display_text(agent_id, escape_terminal_controls),
                display_text(entity, escape_terminal_controls),
            ));
            if let Some(caps) = ap.get("capabilities").and_then(|v| v.as_array()) {
                let cap_strs: Vec<String> = caps
                    .iter()
                    .take(5)
                    .map(|c| {
                        display_text(c.as_str().unwrap_or(""), escape_terminal_controls)
                            .into_owned()
                    })
                    .collect();
                if !cap_strs.is_empty() {
                    out.push_str(&format!("      Capabilities: {}\n", cap_strs.join(", ")));
                }
            }
        }

        if let Some(ref mcp) = agent.mcp_capabilities {
            let si = mcp
                .get("server_info")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let name = si.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
            let version = si.get("version").and_then(|v| v.as_str()).unwrap_or("?");
            out.push_str(&format!(
                "    {}\u{26a1} MCP Server:{} {} v{}\n",
                "\x1b[95m",
                ANSI_RESET,
                display_text(name, escape_terminal_controls),
                display_text(version, escape_terminal_controls),
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
                sig_color,
                detector_name,
                ANSI_RESET,
                display_text(&signal.description, escape_terminal_controls),
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
            out.push_str(&format!(
                "    {}\u{2022} {}{}\n",
                ANSI_DIM,
                display_text(err, escape_terminal_controls),
                ANSI_RESET
            ));
        }
    }

    out.push_str(&format!(
        "\n{}{}{}\n",
        ANSI_BOLD,
        "═".repeat(78),
        ANSI_RESET
    ));
    out.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod terminal_output_tests {
    use super::*;
    use agentsniff::models::{AgentStatus, Confidence, DetectedAgent, DetectorType, Signal};

    #[test]
    fn terminal_text_escapes_control_and_bidi_sequences() {
        let malicious =
            "ok\n\r\t\x1b]52;c;payload\x07\u{061c}\u{200e}\u{2028}\u{2029}\u{202e}\u{206a}txt";
        let escaped = display_text(malicious, true);
        assert!(!escaped.contains('\x1b'));
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
        assert!(!escaped.contains('\t'));
        assert!(!escaped.contains('\u{061c}'));
        assert!(!escaped.contains('\u{200e}'));
        assert!(!escaped.contains('\u{2028}'));
        assert!(!escaped.contains('\u{2029}'));
        assert!(!escaped.contains('\u{202e}'));
        assert!(!escaped.contains('\u{206a}'));
        assert!(escaped.contains("\\n"));
        assert!(escaped.contains("\\u{1b}"));
        assert!(escaped.contains("\\u{2028}"));
        assert!(escaped.contains("\\u{202e}"));
    }

    #[test]
    fn terminal_text_preserves_normal_unicode_and_file_content() {
        let ordinary = "MCP server — café";
        assert_eq!(display_text(ordinary, true), ordinary);

        let forensic = "line one\n\x1b[31mraw";
        assert_eq!(display_text(forensic, false), forensic);
    }

    #[test]
    fn table_rendering_escapes_network_fields_only_for_terminal_display() {
        let remote_value = "remote\x1b]52;c;payload\x07\nforged";
        let mut agent = DetectedAgent::new("host".into(), "192.0.2.10".parse().unwrap());
        agent.agent_type = Some(remote_value.into());
        agent.framework = Some(remote_value.into());
        agent.status = AgentStatus::Detected;
        agent.confidence_score = 0.8;
        agent.confidence_level = "high".into();
        agent.signals.push(Signal::new(
            DetectorType::EndpointProber,
            "test".into(),
            remote_value.into(),
            Confidence::High,
            serde_json::json!({}),
        ));
        agent.signal_count = agent.signals.len();
        agent.agentpin_identity = Some(serde_json::json!({
            "agent_id": remote_value,
            "issuer": remote_value,
            "capabilities": [remote_value],
        }));
        agent.mcp_capabilities = Some(serde_json::json!({
            "server_info": {"name": remote_value, "version": remote_value}
        }));

        let mut result = ScanResult::new();
        result.target_network = remote_value.into();
        result.errors.push(remote_value.into());
        result.agents.push(agent);

        let terminal = render_table(&result, false, true);
        assert!(!terminal.contains(remote_value));
        assert!(terminal.contains("\\u{1b}"));
        assert!(terminal.contains("\\nforged"));

        let explicit_file = render_table(&result, false, false);
        assert!(explicit_file.contains(remote_value));
    }
}
