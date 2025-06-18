use crate::error::{CloudGuardError, Result};
use config::{Config, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;

use crate::llm::structs::LlmProviderType; 

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    pub llm_api_key: String,
    pub llm_provider: LlmProviderType, 
    pub llm_model: String, 
    pub aws: AwsSettings,

}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AwsSettings {
    pub aws_region: String,
    pub aws_secret_access_key: Option<String>,
    pub aws_access_key:  Option<String>,
}



impl Default for Settings {
    fn default() -> Self {
        Self {
            llm_api_key: String::new(),
            llm_provider: LlmProviderType::OpenAI, 
            llm_model: "gpt-4o".to_string(), 
            aws: AwsSettings {
                aws_region:  "us-east-1".to_string(),
                aws_secret_access_key: None,
                aws_access_key: None,
            }
        }
    }
}

impl Settings {
    pub fn new() -> Result<Self> {
        let mut builder = Config::builder()
            // Add config files and environment sources.
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name(&format!("config/{}", env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into()))).required(false))
            .add_source(File::with_name("config/local").required(false))
            // Environment variables with CLOUDGUARD_ prefix will map to struct fields
            // e.g., CLOUDGUARD_LLM_API_KEY -> llm_api_key, CLOUDGUARD_AWS_AWS_REGION -> aws.aws_region
            .add_source(Environment::with_prefix("CLOUDGUARD").separator("_").ignore_empty(true)); 

        // Explicit overrides for direct environment variables (non-CLOUDGUARD_ prefixed)
        // Ensure the key in set_override matches the full path to the struct field name exactly (case-sensitive)
        if let Ok(api_key) = env::var("LLM_API_KEY") {
            builder = builder.set_override("llm_api_key", api_key) 
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }
        if let Ok(provider) = env::var("LLM_PROVIDER") {
            builder = builder.set_override("llm_provider", provider) 
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }
        if let Ok(model) = env::var("LLM_MODEL") {
            builder = builder.set_override("llm_model", model) 
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }
        
        // --- AWS Settings Overrides ---
        if let Ok(region) = env::var("AWS_REGION") {
            // Corrected: Path must be "aws.aws_region" to match the struct field
            builder = builder.set_override("aws.aws_region", region) 
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }
        if let Ok(access_key_id) = env::var("AWS_ACCESS_KEY_ID") { // Renamed 'profile' to 'access_key_id' for clarity
            // Corrected: Path must be "aws.aws_access_key" to match the struct field
            builder = builder.set_override("aws.aws_access_key", access_key_id) 
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }
        
        if let Ok(secret_access_key) = env::var("AWS_SECRET_ACCESS_KEY") { // Corrected env var name from AWS_SECRET_ACCESS_KEY_ID
            // Corrected: Path must be "aws.aws_secret_access_key" to match the struct field
            builder = builder.set_override("aws.aws_secret_access_key", secret_access_key)
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }


        let settings = builder.build()
            .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;

        let config: Settings = settings.try_deserialize()
            .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;

        // Perform final validation.
        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.llm_api_key.is_empty() {
            return Err(CloudGuardError::ConfigError(
                "LLM API key is required. Set LLM_API_KEY environment variable or in config file.".to_string()
            ));
        }

        // You could add more validation here, e.g., check if llm_model is valid for llm_provider
        Ok(())
    }
}
