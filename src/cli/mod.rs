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
        

    }
}