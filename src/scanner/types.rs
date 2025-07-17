use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

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

// IAM User Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamUserInfo {
    pub user_name: String,
    pub user_id: String,
    pub arn: String,
    pub path: String,
    pub create_date: Option<DateTime<Utc>>,
    pub password_last_used: Option<DateTime<Utc>>,
    pub attached_policies: Vec<String>,
    pub inline_policies: Vec<String>,
    pub groups: Vec<String>,
    pub access_keys_count: u32,
    pub has_mfa: bool,
    pub console_access: bool,
    pub tags: HashMap<String, String>,
}

// IAM Role Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamRoleInfo {
    pub role_name: String,
    pub role_id: String,
    pub arn: String,
    pub path: String,
    pub create_date: Option<DateTime<Utc>>,
    pub assume_role_policy_document: Option<String>,
    pub description: Option<String>,
    pub max_session_duration: Option<i32>,
    pub attached_policies: Vec<String>,
    pub inline_policies: Vec<String>,
    pub tags: HashMap<String, String>,
}

// IAM Group Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamGroupInfo {
    pub group_name: String,
    pub group_id: String,
    pub arn: String,
    pub path: String,
    pub create_date: Option<DateTime<Utc>>,
    pub attached_policies: Vec<String>,
    pub inline_policies: Vec<String>,
    pub users: Vec<String>,
}

// IAM Policy Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicyInfo {
    pub policy_name: String,
    pub policy_id: String,
    pub arn: String,
    pub path: String,
    pub default_version_id: String,
    pub attachment_count: i32,
    pub permissions_boundary_usage_count: i32,
    pub is_attachable: bool,
    pub description: Option<String>,
    pub create_date: Option<DateTime<Utc>>,
    pub update_date: Option<DateTime<Utc>>,
    pub policy_document: Option<String>,
    pub tags: HashMap<String, String>,
}

// Password Policy Analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicyInfo {
    pub minimum_password_length: i32,
    pub require_symbols: bool,
    pub require_numbers: bool,
    pub require_uppercase_characters: bool,
    pub require_lowercase_characters: bool,
    pub allow_users_to_change_password: bool,
    pub expire_passwords: bool,
    pub max_password_age: Option<i32>,
    pub password_reuse_prevention: Option<i32>,
    pub hard_expiry: bool,
}

// Access Key Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKeyInfo {
    pub access_key_id: String,
    pub status: String,
    pub create_date: Option<DateTime<Utc>>,
    pub last_used_date: Option<DateTime<Utc>>,
    pub last_used_service: Option<String>,
    pub last_used_region: Option<String>,
    pub age_days: i64,
}

// MFA Device Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaDeviceInfo {
    pub serial_number: String,
    pub device_type: String,
    pub enable_date: Option<DateTime<Utc>>,
}

// Trust Policy Analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicyAnalysis {
    pub allows_any_principal: bool,
    pub allows_cross_account_access: bool,
    pub external_accounts: Vec<String>,
    pub trusted_services: Vec<String>,
    pub has_conditions: bool,
    pub requires_mfa: bool,
    pub requires_external_id: bool,
}

// Permission Analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionAnalysis {
    pub has_admin_access: bool,
    pub has_wildcard_actions: bool,
    pub has_wildcard_resources: bool,
    pub high_risk_actions: Vec<String>,
    pub resource_scope: Vec<String>,
    pub effective_permissions: Vec<String>,
}