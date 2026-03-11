use clap::{Parser, ValueEnum};

use agentsniff::config::ScanConfig;
use agentsniff::scanner::run_scan;
use agentsniff::server::run_server;

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
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
        } => {
            tracing::info!("Scanning network: {}", network);

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
            };
            let scan_config = ScanConfig::from_env_with_defaults(scan_config);

            let result = run_scan(&scan_config, None, None).await?;

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                OutputFormat::Table => {
                    let duration = result
                        .duration_seconds()
                        .map(|d| format!("{:.2}s", d))
                        .unwrap_or_else(|| "?".to_string());

                    println!(
                        "Scan {} complete — {} agent(s) detected in {} ({} detector(s) run, {} error(s))",
                        result.scan_id,
                        result.agents.len(),
                        duration,
                        result.detectors_run.len(),
                        result.errors.len(),
                    );
                    println!(
                        "{:<18} {:<12} {:<8} {:<20} SIGNALS",
                        "IP", "STATUS", "SCORE", "FRAMEWORK"
                    );
                    println!("{}", "-".repeat(72));

                    for agent in &result.agents {
                        let status = format!("{:?}", agent.status).to_lowercase();
                        let score = format!("{:.2}", agent.confidence_score());
                        let framework = agent
                            .framework
                            .as_deref()
                            .unwrap_or("-")
                            .to_string();
                        println!(
                            "{:<18} {:<12} {:<8} {:<20} {}",
                            agent.ip_address,
                            status,
                            score,
                            framework,
                            agent.signals.len(),
                        );
                    }
                }
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

            run_server(scan_config).await?;
        }

        Cli::UpdateSignatures { verify } => {
            tracing::info!("Updating signatures (verify={})", verify);
            println!("Signature update not yet implemented.");
        }
    }

    Ok(())
}
