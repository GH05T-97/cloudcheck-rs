use std::sync::Arc;

// src/aws/client.rs
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_sts::Client as StsClient;
use crate::error::{CloudGuardError, Result};
use tracing::{info, warn};
use dotenvy;

#[derive(Clone)]
pub struct AwsClient {
    pub s3_client: Arc<S3Client>,
    pub sts_client: Arc<StsClient>,
    pub region: String,
}

impl AwsClient {
    pub async fn new() -> Result<Self> { // Removed region and profile arguments
        // Load AWS configuration using default behavior.
        // This automatically handles environment variables (AWS_REGION, AWS_ACCESS_KEY_ID, etc.),
        // shared credential files (~/.aws/credentials, ~/.aws/config), and IAM roles.
        dotenvy::dotenv().ok(); 
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        
        let region_str = config
            .region()
            .map(|r| r.as_ref().to_string())
            .unwrap_or_else(|| "us-east-1".to_string()); // Default to us-east-1 if no region is resolved
            
        info!("Using AWS region: {}", region_str);
        
        // Create AWS service clients using the loaded configuration
        let s3_client = Arc::new(S3Client::new(&config));
        let sts_client = Arc::new(StsClient::new(&config));
        
        match sts_client.get_caller_identity().send().await {
            Ok(response) => {
                if let Some(arn) = response.arn() {
                    info!("Successfully authenticated as: {}", arn);
                } else {
                    info!("Successfully authenticated, but no ARN found.");
                }
            }
            Err(e) => {
            
                warn!("Failed to verify AWS credentials: {}", e);
                return Err(CloudGuardError::AwsError(format!("Authentication failed: {}", e)));
            }
        }
        
        Ok(AwsClient {
            s3_client,
            sts_client,
            region: region_str,
        })
    }
}
