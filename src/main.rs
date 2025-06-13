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
    let settings = Settings::new()?; // No need for mut here if config command is gone
    info!("CloudGuard CLI v{} starting", env!("CARGO_PKG_VERSION"));

    match cli.command { // No need for `&` if you want to consume `cli.command`
        Commands::Scan { service } => { // Removed region and profile from here
            // `region` and `profile` will now be implicitly loaded by the AWS SDK
            // via environment variables or ~/.aws/config/credentials.
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
    // Cloning the AwsClient: This assumes AwsClient is cheap to clone,
    // typically meaning its internal AWS SDK client is wrapped in an Arc.
    // If not, you might need to reconsider how AwsClient is passed around.
    let scanner = S3Scanner::new(aws_client.clone()); 
    
    let findings = scanner.scan().await?;
    info!("Scan complete. Found {} potential issue(s).", findings.len());

    if findings.is_empty() {
        println!("\n✅ No misconfigurations found in S3 buckets!");
        return Ok(());
    }

    // Check for API key before proceeding
    if settings.openai_api_key.trim().is_empty() {
        error!("OpenAI API key is not set. Cannot analyze findings.");
        println!("Please set the OPENAI_API_KEY environment variable.");
        return Err(anyhow::anyhow!("API key missing"));
    }
    
    info!("Analyzing findings with LLM...");
    let llm_client = LlmClient::new(&settings.openai_api_key)?;
    
    let analysis = llm_client.analyze_s3_findings(&findings).await?;
    
    info!("Formatting report...");
    let formatter = ReportFormatter::new();
    formatter.display_s3_report(&findings, &analysis).await?;

    Ok(())
}
