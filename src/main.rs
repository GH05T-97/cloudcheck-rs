use anyhow::Result;
use clap::Parser;
use cloudguard_cli::{
    cli::{Cli, Commands},
    config::Settings,
    aws::AwsClient,
    scanner::S3Scanner,
    llm::LlmClient,
    output::ReportFormatter,
};
use tracing::{info, error};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("cloudguard_cli=info")
        .init();

    let cli = Cli::parse();
    
    // Load configuration
    let settings = Settings::new()?;
    info!("CloudGuard CLI v{} starting", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Commands::Scan { service, region, profile } => {
            scan_command(service, region, profile, &settings).await?;
        }
        Commands::Config { set_api_key } => {
            config_command(set_api_key, &settings).await?;
        }
    }

    Ok(())
}

async fn scan_command(
    service: String,
    region: Option<String>,
    profile: Option<String>,
    settings: &Settings,
) -> Result<()> {
    match service.as_str() {
        "s3" => {
            info!("Starting S3 bucket scan");
            
            // Initialize AWS client
            let aws_client = AwsClient::new(region, profile).await?;
            
            // Initialize scanner
            let scanner = S3Scanner::new(aws_client);
            
            // Perform scan
            let findings = scanner.scan().await?;
            info!("Found {} potential issues", findings.len());

            if !findings.is_empty() {
                // Initialize LLM client
                let llm_client = LlmClient::new(&settings.openai_api_key)?;
                
                // Analyze findings with LLM
                let analysis = llm_client.analyze_s3_findings(&findings).await?;
                
                // Format and display results
                let formatter = ReportFormatter::new();
                formatter.display_s3_report(&findings, &analysis).await?;
            } else {
                println!("✅ No security issues found in S3 buckets!");
            }
        }
        _ => {
            error!("Service '{}' not supported yet", service);
            return Err(anyhow::anyhow!("Unsupported service: {}", service));
        }
    }

    Ok(())
}

async fn config_command(api_key: Option<String>, _settings: &Settings) -> Result<()> {
    if let Some(key) = api_key {
        // Store API key securely (for now, just inform user)
        println!("API key configuration would be stored here");
        println!("For now, please set the OPENAI_API_KEY environment variable");
        println!("export OPENAI_API_KEY='{}'", key);
    } else {
        println!("Current configuration:");
        println!("OpenAI API Key: {}", if std::env::var("OPENAI_API_KEY").is_ok() { "Set" } else { "Not set" });
    }
    
    Ok(())
}