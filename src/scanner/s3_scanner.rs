use crate::{
    aws::AwsClient,
    scanner::types::*,
    error::{CloudGuardError, Result},
};
use aws_sdk_s3::types::{BucketLocationConstraint, Grant, Permission};
use chrono::{DateTime, Utc};
use serde_json::json;
use tracing::{info, warn, debug};
use uuid::Uuid;

pub struct S3Scanner {
    aws_client: AwsClient,
}

impl S3Scanner {
    pub fn new(aws_client: AwsClient) -> Self {
        Self { aws_client }
    }

    pub async fn scan(&self) -> Result<Vec<Finding>> {
        info!("Starting S3 bucket scan");
        let mut findings = Vec::new();
        
        // List all buckets
        let buckets_response = self.aws_client.s3_client
            .list_buckets()
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?;

        let buckets = buckets_response.buckets().unwrap_or(&[]);
        info!("Found {} S3 buckets to scan", buckets.len());

        for bucket in buckets {
            if let Some(bucket_name) = bucket.name() {
                debug!("Scanning bucket: {}", bucket_name);
                
                let bucket_info = self.analyze_bucket(bucket_name).await?;
                let bucket_findings = self.generate_findings(&bucket_info).await?;
                findings.extend(bucket_findings);
            }
        }

        info!("S3 scan completed with {} findings", findings.len());
        Ok(findings)
    }

    async fn analyze_bucket(&self, bucket_name: &str) -> Result<S3BucketInfo> {
        let mut bucket_info = S3BucketInfo {
            name: bucket_name.to_string(),
            region: self.aws_client.region.clone(),
            creation_date: None,
            public_read: false,
            public_write: false,
            encryption_enabled: false,
            encryption_type: None,
            versioning_enabled: false,
            logging_enabled: false,
            mfa_delete: false,
            lifecycle_rules: Vec::new(),
            replication_rules: Vec::new(),
            object_count: None,
            total_size_bytes: None,
        };

        // Get bucket location
        if let Ok(location_response) = self.aws_client.s3_client
            .get_bucket_location()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(constraint) = location_response.location_constraint() {
                match constraint {
                    BucketLocationConstraint::Eu => bucket_info.region = "eu-west-1".to_string(),
                    BucketLocationConstraint::EuWest1 => bucket_info.region = "eu-west-1".to_string(),
                    BucketLocationConstraint::UsWest1 => bucket_info.region = "us-west-1".to_string(),
                    BucketLocationConstraint::UsWest2 => bucket_info.region = "us-west-2".to_string(),
                    BucketLocationConstraint::ApSouth1 => bucket_info.region = "ap-south-1".to_string(),
                    BucketLocationConstraint::ApSoutheast1 => bucket_info.region = "ap-southeast-1".to_string(),
                    BucketLocationConstraint::ApSoutheast2 => bucket_info.region = "ap-southeast-2".to_string(),
                    BucketLocationConstraint::ApNortheast1 => bucket_info.region = "ap-northeast-1".to_string(),
                    BucketLocationConstraint::SaEast1 => bucket_info.region = "sa-east-1".to_string(),
                    BucketLocationConstraint::CnNorth1 => bucket_info.region = "cn-north-1".to_string(),
                    BucketLocationConstraint::EuCentral1 => bucket_info.region = "eu-central-1".to_string(),
                    _ => {} // Keep default region
                }
            }
        }

        // Check public access
        self.check_public_access(bucket_name, &mut bucket_info).await?;

        // Check encryption
        self.check_encryption(bucket_name, &mut bucket_info).await?;

        // Check versioning
        self.check_versioning(bucket_name, &mut bucket_info).await?;

        // Check logging
        self.check_logging(bucket_name, &mut bucket_info).await?;

        // Check lifecycle rules
        self.check_lifecycle(bucket_name, &mut bucket_info).await?;

        // Check replication
        self.check_replication(bucket_name, &mut bucket_info).await?;

        Ok(bucket_info)
    }

    async fn check_public_access(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        // Check bucket ACL
        if let Ok(acl_response) = self.aws_client.s3_client
            .get_bucket_acl()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(grants) = acl_response.grants() {
                for grant in grants {
                    if let Some(grantee) = grant.grantee() {
                        if let Some(uri) = grantee.uri() {
                            if uri.contains("AllUsers") {
                                match grant.permission() {
                                    Some(Permission::Read) | Some(Permission::FullControl) => {
                                        bucket_info.public_read = true;
                                    }
                                    Some(Permission::Write) | Some(Permission::WriteAcp) => {
                                        bucket_info.public_write = true;
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check bucket policy for public access
        if let Ok(policy_response) = self.aws_client.s3_client
            .get_bucket_policy()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(policy) = policy_response.policy() {
                // Simple check for public access in policy
                if policy.contains("\"Principal\": \"*\"") || policy.contains("\"Principal\":\"*\"") {
                    bucket_info.public_read = true;
                }
            }
        }

        Ok(())
    }

    async fn check_encryption(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(encryption_response) = self.aws_client.s3_client
            .get_bucket_encryption()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(config) = encryption_response.server_side_encryption_configuration() {
                if let Some(rules) = config.rules() {
                    if !rules.is_empty() {
                        bucket_info.encryption_enabled = true;
                        if let Some(rule) = rules.first() {
                            if let Some(default_encryption) = rule.apply_server_side_encryption_by_default() {
                                bucket_info.encryption_type = default_encryption.sse_algorithm().map(|a| a.as_str().to_string());
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn check_versioning(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(versioning_response) = self.aws_client.s3_client
            .get_bucket_versioning()
            .bucket(bucket_name)
            .send()
            .await
        {
            bucket_info.versioning_enabled = versioning_response.status()
                .map(|s| s.as_str() == "Enabled")
                .unwrap_or(false);
                
            bucket_info.mfa_delete = versioning_response.mfa_delete()
                .map(|m| m.as_str() == "Enabled")
                .unwrap_or(false);
        }

        Ok(())
    }

    async fn check_logging(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(logging_response) = self.aws_client.s3_client
            .get_bucket_logging()
            .bucket(bucket_name)
            .send()
            .await
        {
            bucket_info.logging_enabled = logging_response.logging_enabled().is_some();
        }

        Ok(())
    }

    async fn check_lifecycle(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(lifecycle_response) = self.aws_client.s3_client
            .get_bucket_lifecycle_configuration()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(rules) = lifecycle_response.rules() {
                for rule in rules {
                    let lifecycle_rule = LifecycleRule {
                        id: rule.id().unwrap_or("").to_string(),
                        status: rule.status().as_str().to_string(),
                        filter: rule.filter().and_then(|f| f.prefix()).map(|p| p.to_string()),
                        transitions: rule.transitions().map(|transitions| {
                            transitions.iter().map(|t| LifecycleTransition {
                                days: t.days(),
                                storage_class: t.storage_class().map(|sc| sc.as_str().to_string()).unwrap_or_default(),
                            }).collect()
                        }).unwrap_or_default(),
                    };
                    bucket_info.lifecycle_rules.push(lifecycle_rule);
                }
            }
        }

        Ok(())
    }

    async fn check_replication(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(replication_response) = self.aws_client.s3_client
            .get_bucket_replication()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(config) = replication_response.replication_configuration() {
                if let Some(rules) = config.rules() {
                    for rule in rules {
                        if let Some(destination) = rule.destination() {
                            let replication_rule = ReplicationRule {
                                id: rule.id().unwrap_or("").to_string(),
                                status: rule.status().as_str().to_string(),
                                destination_bucket: destination.bucket().unwrap_or("").to_string(),
                                destination_region: destination.storage_class().map(|sc| sc.as_str().to_string()).unwrap_or_default(),
                            };
                            bucket_info.replication_rules.push(replication_rule);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn generate_findings(&self, bucket_info: &S3BucketInfo) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();

        // Security findings
        if bucket_info.public_read {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "S3 Bucket Publicly Readable".to_string(),
                description: format!("Bucket '{}' allows public read access", bucket_info.name),
                severity: Severity::High,
                category: Category::Security,
                resource_type: "S3Bucket".to_string(),
                resource_id: bucket_info.name.clone(),
                region: bucket_info.region.clone(),
                details: json!({"public_read": true}),
                discovered_at: now,
            });
        }

        if bucket_info.public_write {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "S3 Bucket Publicly Writable".to_string(),
                description: format!("Bucket '{}' allows public write access", bucket_info.name),
                severity: Severity::Critical,
                category: Category::Security,
                resource_type: "S3Bucket".to_string(),
                resource_id: bucket_info.name.clone(),
                region: bucket_info.region.clone(),
                details: json!({"public_write": true}),
                discovered_at: now,
            });
        }

        if !bucket_info.encryption_enabled {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "S3 Bucket Encryption Disabled".to_string(),
                description: format!("Bucket '{}' does not have encryption enabled", bucket_info.name),
                severity: Severity::Medium,
                category: Category::Security,
                resource_type: "S3Bucket".to_string(),
                resource_id: bucket_info.name.clone(),
                region: bucket_info.region.clone(),
                details: json!({"encryption_enabled": false}),
                discovered_at: now,
            });
        }
    }
}