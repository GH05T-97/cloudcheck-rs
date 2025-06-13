use anyhow::Result;
use clap::Parser;
use cloudguard_cli::{
    cli::{Cli, Commands},
    config::Settings,
    aws::AwsClient, // Assuming AwsClient handles AWS config loading internally
    scanner::S3Scanner,
    llm::LlmClient,
    output::ReportFormatter,
};
use tracing::{info, error, warn};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging for application-level feedback
    tracing_subscriber::fmt()
        .with_env_filter("cloudguard_cli=info")
        .without_time() 
        .init();

    let cli = Cli::parse();
    
    // Load configuration from a file or environment variables
    let settings = Settings::new()?; 
    info!("CloudGuard CLI v{} starting", env!("CARGO_PKG_VERSION"));

    match cli.command { 
        Commands::Scan { service } => { 
            scan_command(
                service, 
                &settings // Pass settings reference
            ).await?;
        }
    }

    Ok(())
}

/// Handles the 'scan' command, acting as a dispatcher for different services.
async fn scan_command(
    service: String,
    settings: &Settings, // No region or profile args here either
) -> Result<()> {
    info!("Initializing AWS client from environment/config...");
    // AwsClient::new() should now internally load AWS config from environment variables
    // or shared credential files, without explicit region/profile arguments.
    let aws_client = AwsClient::new().await?; // No arguments passed
    info!("AWS client initialized for region: {}", aws_client.region); // Assuming AwsClient stores the resolved region

    // Dispatch to the appropriate handler based on the service name
    Ok(match service.as_str() {
        "s3" => {
            info!("Delegating to S3 scanner.");
            handle_s3_scan(&aws_client, settings).await?
        }
        "ec2" | "lambda" | "dynamodb" => {
            // Add placeholders for future service implementations
            warn!("Scanner for '{}' is not yet implemented.", service);
        }
        _ => {
            error!("Service '{}' not supported.", service);
            return Err(anyhow::anyhow!("Unsupported service: {}", service));
        }
    })
}

/// Contains the specific logic for scanning S3 buckets.
async fn handle_s3_scan(aws_client: &AwsClient, settings: &Settings) -> Result<()> {
    info!("Starting S3 bucket scan...");
    let scanner = S3Scanner::new(aws_client.clone()); 
    
    let findings = scanner.scan().await?;
    info!("Scan complete. Found {} potential issue(s).", findings.len());

    if findings.is_empty() {
        println!("\n✅ No misconfigurations found in S3 buckets!");
        return Ok(());
    }

    // Check for API key before proceeding
    if settings.llm_api_key.trim().is_empty() {
        error!("LLM API key is not set. Cannot analyze findings.");
        println!("Please set the LLM_API_KEY environment variable.");
        return Err(anyhow::anyhow!("API key missing"));
    }
    
    info!("Analyzing findings with LLM using {:?} (model: {})...", 
        settings.llm_provider, settings.llm_model
    );

    let llm_client = LlmClient::new(
        &settings.llm_api_key,          // Pass API key reference
        settings.llm_provider.clone(),  // Clone the enum for ownership
        &settings.llm_model             // Pass model name reference
    )?;
    
    let analysis = llm_client.analyze_s3_findings(&findings).await?;
    
    info!("Formatting report...");
    let formatter = ReportFormatter::new();
    formatter.display_s3_report(&findings, &analysis).await?;

    Ok(())
}
