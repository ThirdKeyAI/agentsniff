use std::fs;

use clap::{Parser, ValueEnum};

use agentsniff::config::ScanConfig;
use agentsniff::ebpf::try_load_ebpf;
use agentsniff::sarif_export::to_sarif;
use agentsniff::scanner::run_scan;
use agentsniff::server::run_server;
use agentsniff::signatures::SignatureData;

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
        network: String,

        /// Output format
        #[arg(long, value_enum, default_value = "table")]
        format: OutputFormat,

        /// Optional path to a YAML config file
        #[arg(long)]
        config: Option<String>,

        /// Write output to a file instead of stdout
        #[arg(long)]
        output_file: Option<String>,

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
        #[arg(long, default_value = "9090")]
        port: u16,

        /// Host address to bind to
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Optional path to a YAML config file
        #[arg(long)]
        config: Option<String>,
    },
    /// Update detection signatures from GitHub
    UpdateSignatures {
        /// Verify signatures after update
        #[arg(long, default_value = "true")]
        verify: bool,

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
    tracing_subscriber::fmt()
        .with_env_filter("agentsniff=info")
        .init();

    let cli = Cli::parse();

    match cli {
        Cli::Scan {
            network,
            format,
            config,
            output_file,
            verbose,
            quiet,
        } => {
            if verbose {
                tracing::info!("Scanning network: {}", network);
            }

            // Load base config from YAML if provided, otherwise use defaults
            let mut scan_config = if let Some(path) = config {
                ScanConfig::from_yaml_file(&path)?
            } else {
                ScanConfig::default()
            };

            // Apply CLI args and env overrides
            scan_config.target_network = network;
            scan_config.output_format = match format {
                OutputFormat::Table => "table".to_string(),
                OutputFormat::Json => "json".to_string(),
                OutputFormat::Csv => "csv".to_string(),
                OutputFormat::Sarif => "sarif".to_string(),
            };
            let scan_config = ScanConfig::from_env_with_defaults(scan_config);

            let result = run_scan(&scan_config, None, None, None).await?;

            let output = match format {
                OutputFormat::Json => serde_json::to_string_pretty(&result)?,
                OutputFormat::Sarif => {
                    let sarif_value = to_sarif(&result);
                    serde_json::to_string_pretty(&sarif_value)?
                }
                OutputFormat::Csv => {
                    let mut lines =
                        vec!["IP,STATUS,SCORE,FRAMEWORK,SIGNALS".to_string()];
                    for agent in &result.agents {
                        let status = format!("{:?}", agent.status).to_lowercase();
                        let score = format!("{:.2}", agent.confidence_score);
                        let framework =
                            agent.framework.as_deref().unwrap_or("-").to_string();
                        lines.push(format!(
                            "{},{},{},{},{}",
                            agent.ip_address,
                            status,
                            score,
                            framework,
                            agent.signals.len(),
                        ));
                    }
                    lines.join("\n")
                }
                OutputFormat::Table => {
                    let mut out = String::new();
                    if !quiet {
                        let duration = result
                            .duration_seconds()
                            .map(|d| format!("{:.2}s", d))
                            .unwrap_or_else(|| "?".to_string());

                        out.push_str(&format!(
                            "Scan {} complete — {} agent(s) detected in {} ({} detector(s) run, {} error(s))\n",
                            result.scan_id,
                            result.agents.len(),
                            duration,
                            result.detectors_run.len(),
                            result.errors.len(),
                        ));
                        out.push_str(&format!(
                            "{:<18} {:<12} {:<8} {:<20} SIGNALS\n",
                            "IP", "STATUS", "SCORE", "FRAMEWORK"
                        ));
                        out.push_str(&format!("{}\n", "-".repeat(72)));
                    }

                    for agent in &result.agents {
                        let status =
                            format!("{:?}", agent.status).to_lowercase();
                        let score = format!("{:.2}", agent.confidence_score);
                        let framework = agent
                            .framework
                            .as_deref()
                            .unwrap_or("-")
                            .to_string();
                        out.push_str(&format!(
                            "{:<18} {:<12} {:<8} {:<20} {}\n",
                            agent.ip_address,
                            status,
                            score,
                            framework,
                            agent.signals.len(),
                        ));
                    }
                    // Trim trailing newline for consistent behaviour
                    out.trim_end_matches('\n').to_string()
                }
            };

            if let Some(path) = output_file {
                fs::write(&path, format!("{}\n", output))?;
                if !quiet {
                    println!("Output written to {}", path);
                }
            } else if !quiet || matches!(format, OutputFormat::Json | OutputFormat::Csv | OutputFormat::Sarif) {
                println!("{}", output);
            }
        }

        Cli::Serve { port, host, config } => {
            tracing::info!("Starting server on {}:{}", host, port);

            let mut scan_config = if let Some(path) = config {
                ScanConfig::from_yaml_file(&path)?
            } else {
                ScanConfig::default()
            };

            scan_config.api_port = port;
            scan_config.api_host = host;
            let scan_config = ScanConfig::from_env_with_defaults(scan_config);

            // Print startup info
            let sigs = SignatureData::load_with_overlay();
            let verified = sigs
                .verification_status
                .values()
                .filter(|v| **v == agentsniff::signatures::VerificationStatus::Verified)
                .count();
            let total = sigs.verification_status.len();
            println!("agentsniff v2.0.0-alpha.1");

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

        Cli::UpdateSignatures { verify, url } => {
            if !verify {
                println!("Warning: signature verification is disabled.");
            }
            agentsniff::signatures::updater::update_signatures(
                verify,
                url.as_deref(),
            )
            .await?;
        }

        Cli::InitConfig { output, force } => {
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
