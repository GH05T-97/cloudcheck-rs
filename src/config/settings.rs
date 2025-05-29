use crate::error::{CloudGuardError, Result};
use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    pub openai_api_key: String,
    pub aws: AwsSettings,
    pub output: OutputSettings,
    pub logging: LoggingSettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AwsSettings {
    pub default_region: String,
    pub profile: Option<String>,
    pub assume_role_arn: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutputSettings {
    pub format: String, // json, table, summary
    pub verbose: bool,
    pub save_to_file: bool,
    pub output_directory: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoggingSettings {
    pub level: String,
    pub format: String, // json, pretty
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            openai_api_key: String::new(),
            aws: AwsSettings {
                default_region: "us-east-1".to_string(),
                profile: None,
                assume_role_arn: None,
            },
            output: OutputSettings {
                format: "table".to_string(),
                verbose: false,
                save_to_file: false,
                output_directory: "./reports".to_string(),
            },
            logging: LoggingSettings {
                level: "info".to_string(),
                format: "pretty".to_string(),
            },
        }
    }
}

impl Settings {
    pub fn new() -> Result<Self> {
        let mut settings = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name(&format!("config/{}", env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into()))).required(false))
            .add_source(File::with_name("config/local").required(false))
            .add_source(Environment::with_prefix("CLOUDGUARD").separator("_"))
            .build()
            .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;

        // Override with environment variables
        if let Ok(api_key) = env::var("OPENAI_API_KEY") {
            settings.set("openai_api_key", api_key)
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }

        if let Ok(region) = env::var("AWS_DEFAULT_REGION") {
            settings.set("aws.default_region", region)
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }

        if let Ok(profile) = env::var("AWS_PROFILE") {
            settings.set("aws.profile", profile)
                .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;
        }

        let mut config: Settings = settings.try_deserialize()
            .map_err(|e| CloudGuardError::ConfigError(e.to_string()))?;

        // Ensure we have an API key
        if config.openai_api_key.is_empty() {
            config.openai_api_key = env::var("OPENAI_API_KEY")
                .unwrap_or_default();
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.openai_api_key.is_empty() {
            return Err(CloudGuardError::ConfigError(
                "OpenAI API key is required. Set OPENAI_API_KEY environment variable.".to_string()
            ));
        }

        Ok(())
    }
}