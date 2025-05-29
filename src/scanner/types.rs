use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Category {
    Security,
    CostOptimization,
    Performance,
    DisasterRecovery,
    Compliance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub resource_type: String,
    pub resource_id: String,
    pub region: String,
    pub details: serde_json::Value,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3BucketInfo {
    pub name: String,
    pub region: String,
    pub creation_date: Option<DateTime<Utc>>,
    pub public_read: bool,
    pub public_write: bool,
    pub encryption_enabled: bool,
    pub encryption_type: Option<String>,
    pub versioning_enabled: bool,
    pub logging_enabled: bool,
    pub mfa_delete: bool,
    pub lifecycle_rules: Vec<LifecycleRule>,
    pub replication_rules: Vec<ReplicationRule>,
    pub object_count: Option<u64>,
    pub total_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleRule {
    pub id: String,
    pub status: String,
    pub filter: Option<String>,
    pub transitions: Vec<LifecycleTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransition {
    pub days: Option<i32>,
    pub storage_class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRule {
    pub id: String,
    pub status: String,
    pub destination_bucket: String,
    pub destination_region: String,
}