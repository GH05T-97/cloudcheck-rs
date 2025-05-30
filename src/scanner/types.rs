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
    pub public_access_block_enabled: bool,
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
    pub ssl_requests_only: bool,
    pub cors_configured: bool,
    pub cors_allows_all_origins: bool,
    pub website_hosting_enabled: bool,
    pub notification_config_exists: bool,
    pub object_lock_enabled: bool,
    pub object_lock_retention: Option<String>,
    pub intelligent_tiering_enabled: bool,
    pub inventory_enabled: bool,
    pub analytics_enabled: bool,
    pub metrics_enabled: bool,
    pub estimated_monthly_cost: Option<f64>,
    pub storage_class_breakdown: std::collections::HashMap<String, u64>,
    pub old_objects_count: u64, // Objects >30 days in Standard
    pub lifecycle_cost_optimization_score: u8, // 0-100
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