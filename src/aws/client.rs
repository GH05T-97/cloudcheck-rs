// src/aws/client.rs
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_sts::Client as StsClient;
use crate::error::{CloudGuardError, Result};
use tracing::{info, warn};

#[derive(Clone)]
pub struct AwsClient {
    pub s3_client: S3Client,
    pub sts_client: StsClient,
    pub region: String,
}

impl AwsClient {
    pub async fn new(region: Option<String>, profile: Option<String>) -> Result<Self> {
        let mut config_loader = aws_config::defaults(BehaviorVersion::latest());
        
        // Set region if provided
        if let Some(region_str) = &region {
            config_loader = config_loader.region(Region::new(region_str.clone()));
        }
        
        // Set profile if provided
        if let Some(profile_name) = &profile {
            config_loader = config_loader.profile_name(profile_name);
        }
        
        let config = config_loader.load().await;
        
        let region_str = config
            .region()
            .map(|r| r.as_ref().to_string())
            .unwrap_or_else(|| "us-east-1".to_string());
            
        info!("Using AWS region: {}", region_str);
        
        let s3_client = S3Client::new(&config);
        let sts_client = StsClient::new(&config);
        
        // Verify credentials
        match sts_client.get_caller_identity().send().await {
            Ok(response) => {
                if let Some(arn) = response.arn() {
                    info!("Successfully authenticated as: {}", arn);
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