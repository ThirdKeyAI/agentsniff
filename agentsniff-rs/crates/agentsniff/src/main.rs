use clap::Parser;

#[derive(Parser)]
#[command(name = "agentsniff", version, about = "AI Agent Network Scanner")]
enum Cli {
    /// Scan a network for AI agents
    Scan {
        /// Target network in CIDR notation (e.g., 192.168.1.0/24)
        network: String,
    },
    /// Start the web dashboard server
    Serve {
        /// Port to listen on
        #[arg(long, default_value = "9090")]
        port: u16,
    },
    /// Update detection signatures from GitHub
    UpdateSignatures {
        /// Verify signatures after update
        #[arg(long, default_value = "true")]
        verify: bool,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("agentsniff=info")
        .init();

    let cli = Cli::parse();

    match cli {
        Cli::Scan { network } => {
            tracing::info!("Scanning network: {}", network);
        }
        Cli::Serve { port } => {
            tracing::info!("Starting server on port {}", port);
        }
        Cli::UpdateSignatures { verify } => {
            tracing::info!("Updating signatures (verify={})", verify);
        }
    }

    Ok(())
}
