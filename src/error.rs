use thiserror::Error;

pub type Result<T> = std::result::Result<T, CloudGuardError>;

#[derive(Error, Debug)]
pub enum CloudGuardError {
    #[error("AWS error: {0}")]
    AwsError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("LLM API error: {0}")]
    LlmError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Generic error: {0}")]
    Other(String),
}

impl From<aws_sdk_s3::Error> for CloudGuardError {
    fn from(err: aws_sdk_s3::Error) -> Self {
        CloudGuardError::AwsError(err.to_string())
    }
}

impl From<config::ConfigError> for CloudGuardError {
    fn from(err: config::ConfigError) -> Self {
        CloudGuardError::ConfigError(err.to_string())
    }
}