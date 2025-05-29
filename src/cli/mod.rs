use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cloudguard")]
#[command(about = "Multi-cloud security scanner")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan cloud resources for security issues
    Scan {
        /// Service to scan (s3, lambda, iam, etc.)
        service: String,
        
        /// AWS region to scan
        #[arg(short, long)]
        region: Option<String>,
        
        /// AWS profile to use
        #[arg(short, long)]
        profile: Option<String>,
    },
    /// Configure CLI settings
    Config {
        /// Set OpenAI API key
        #[arg(long)]
        set_api_key: Option<String>,
    },
}