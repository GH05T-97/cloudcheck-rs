use crate::{
    aws::AwsClient,
    scanner::types::*,
    error::{CloudGuardError, Result},
};
use aws_sdk_s3::types::{BucketLocationConstraint, Permission};
use chrono::{Utc};
use serde_json::json;
use tracing::{info, debug};
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

        let buckets = buckets_response.buckets();
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
            public_access_block_enabled: false,
            block_public_acls: false,
            ignore_public_acls: false,
            block_public_policy: false,
            restrict_public_buckets: false,
            ssl_requests_only: false,
            cors_configured: false,
            cors_allows_all_origins: false,
            website_hosting_enabled: false,
            object_lock_enabled: false,
            object_lock_retention: None,
            intelligent_tiering_enabled: false,
            old_objects_count: 0,
            storage_class_breakdown: std::collections::HashMap::new(),
            lifecycle_cost_optimization_score: 0,
            notification_config_exists: false,
            inventory_enabled: false,
            analytics_enabled: false,
            metrics_enabled: false,
            estimated_monthly_cost: Some(0.00),
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

        self.check_public_access_block(bucket_name, &mut bucket_info).await?;
        self.check_ssl_enforcement(bucket_name, &mut bucket_info).await?;
        self.check_cors_configuration(bucket_name, &mut bucket_info).await?;
        self.check_object_lock(bucket_name, &mut bucket_info).await?;
        self.check_intelligent_tiering(bucket_name, &mut bucket_info).await?;
        self.analyze_storage_classes(bucket_name, &mut bucket_info).await?;

        Ok(bucket_info)
    }

        async fn check_public_access_block(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(pab_response) = self.aws_client.s3_client
            .get_public_access_block()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(config) = pab_response.public_access_block_configuration() {
                bucket_info.public_access_block_enabled = true;
                bucket_info.block_public_acls = config.block_public_acls().unwrap_or(false);
                bucket_info.ignore_public_acls = config.ignore_public_acls().unwrap_or(false);
                bucket_info.block_public_policy = config.block_public_policy().unwrap_or(false);
                bucket_info.restrict_public_buckets = config.restrict_public_buckets().unwrap_or(false);
            }
        }
        Ok(())
    }

    async fn check_ssl_enforcement(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(policy_response) = self.aws_client.s3_client
            .get_bucket_policy()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(policy) = policy_response.policy() {
                // Check for SSL-only policy
                bucket_info.ssl_requests_only = policy.contains("aws:SecureTransport") 
                    && policy.contains("\"Bool\":{\"aws:SecureTransport\":\"false\"}")
                    && policy.contains("\"Effect\":\"Deny\"");
            }
        }
        Ok(())
    }

    async fn check_cors_configuration(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(cors_response) = self.aws_client.s3_client
            .get_bucket_cors()
            .bucket(bucket_name)
            .send()
            .await
        {
            bucket_info.cors_configured = true;
            for rule in cors_response.cors_rules() {
                for origin in rule.allowed_origins() {
                    if origin == "*" {
                        bucket_info.cors_allows_all_origins = true;
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    async fn check_object_lock(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(lock_response) = self.aws_client.s3_client
            .get_object_lock_configuration()
            .bucket(bucket_name)
            .send()
            .await
        {
            if let Some(config) = lock_response.object_lock_configuration() {
                bucket_info.object_lock_enabled = config.object_lock_enabled()
                    .map(|s| s.as_str() == "Enabled")
                    .unwrap_or(false);
                    
                if let Some(rule) = config.rule() {
                    if let Some(retention) = rule.default_retention() {
                        bucket_info.object_lock_retention = Some(format!("{:?}", retention));
                    }
                }
            }
        }
        Ok(())
        }

        async fn analyze_storage_classes(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        // List objects and analyze storage classes
        let mut continuation_token: Option<String> = None;
        let mut old_objects = 0u64;
        let mut storage_breakdown = std::collections::HashMap::new();
        
        loop {
            let mut request = self.aws_client.s3_client
                .list_objects_v2()
                .bucket(bucket_name)
                .max_keys(1000);
                
            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }
            
            match request.send().await {
                Ok(response) => {
                    for object in response.contents() {
                        let storage_class = object.storage_class()
                            .map(|sc| sc.as_str().to_string())
                            .unwrap_or_else(|| "STANDARD".to_string());
                        
                        *storage_breakdown.entry(storage_class.clone()).or_insert(0) += 1;
                        
                        // Check if STANDARD storage is old (>30 days)
                        if storage_class == "STANDARD" {
                            if let Some(last_modified) = object.last_modified() {
                                let secs = last_modified.secs();
                                let chrono_time = chrono::DateTime::<Utc>::from_timestamp(secs, 0)
                                    .unwrap_or_else(|| chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap());
                                let age = Utc::now() - chrono_time;
                                if age.num_days() > 30 {
                                    old_objects += 1;
                                }
                            }
                        }
                    }
                    
                    if response.is_truncated().unwrap_or(false) {
                        continuation_token = response.next_continuation_token().map(|s| s.to_string());
                    } else {
                        break;
                    }
                },
                Err(_) => break, // Handle error appropriately
            }
        }
        
        bucket_info.storage_class_breakdown = storage_breakdown;
        bucket_info.old_objects_count = old_objects;
        
        Ok(())
    }

    async fn check_intelligent_tiering(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        if let Ok(it_response) = self.aws_client.s3_client
            .list_bucket_intelligent_tiering_configurations()
            .bucket(bucket_name)
            .send()
            .await
        {
            bucket_info.intelligent_tiering_enabled = !it_response.intelligent_tiering_configuration_list().is_empty();
        }
        Ok(())
    }

    // Add WAF-specific findings
    async fn generate_waf_findings(&self, bucket_info: &S3BucketInfo) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();
        
        // SEC-01: Public Access Block not enabled (Critical WAF gap)
        if !bucket_info.public_access_block_enabled {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF SEC-01: Public Access Block Not Configured".to_string(),
                description: format!(
                    "Bucket '{}' lacks Public Access Block configuration. AWS Well-Architected Security Pillar requires this control.",
                    bucket_info.name
                ),
                severity: Severity::High,
                category: Category::Security,
                resource_type: "S3Bucket".to_string(),
                resource_id: bucket_info.name.clone(),
                region: bucket_info.region.clone(),
                details: json!({
                    "waf_pillar": "Security",
                    "waf_question": "SEC-01",
                    "compliance_gap": "Public Access Block",
                    "business_impact": "Potential data exposure risk",
                    "recommended_action": "Enable Public Access Block settings"
                }),
                discovered_at: now,
            });
        }
        
        // SEC-08: SSL-only access not enforced
        if !bucket_info.ssl_requests_only {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF SEC-08: Data in Transit Not Protected".to_string(),
                description: format!(
                    "Bucket '{}' does not enforce SSL-only access. Data in transit protection required by WAF.",
                    bucket_info.name
                ),
                severity: Severity::Medium,
                category: Category::Security,
                resource_type: "S3Bucket".to_string(),
                resource_id: bucket_info.name.clone(),
                region: bucket_info.region.clone(),
                details: json!({
                    "waf_pillar": "Security",
                    "waf_question": "SEC-08",
                    "compliance_gap": "SSL enforcement",
                    "estimated_risk": "Man-in-the-middle attacks",
                    "recommended_action": "Add bucket policy requiring SSL"
                }),
                discovered_at: now,
            });
        }
        
        // COST-07: Storage class optimization opportunity
        if bucket_info.old_objects_count > 0 && bucket_info.lifecycle_rules.is_empty() {
            let estimated_savings = (bucket_info.old_objects_count as f64) * 0.0125 * 30.0; // Rough calculation
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF COST-07: Storage Class Optimization Opportunity".to_string(),
                description: format!(
                    "Bucket '{}' has {} objects in STANDARD storage >30 days old without lifecycle policies",
                    bucket_info.name, bucket_info.old_objects_count
                ),
                severity: Severity::Low,
                category: Category::CostOptimization,
                resource_type: "S3Bucket".to_string(),
                resource_id: bucket_info.name.clone(),
                region: bucket_info.region.clone(),
                details: json!({
                    "waf_pillar": "Cost Optimization",
                    "waf_question": "COST-07",
                    "optimization_opportunity": "Lifecycle policies",
                    "estimated_monthly_savings_gbp": estimated_savings,
                    "objects_affected": bucket_info.old_objects_count,
                    "recommended_action": "Implement lifecycle policies for IA/Glacier transition"
                }),
                discovered_at: now,
            });
        }
        
        // REL-09: Backup strategy assessment
        if !bucket_info.versioning_enabled && bucket_info.replication_rules.is_empty() {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF REL-09: Insufficient Backup Strategy".to_string(),
                description: format!(
                    "Bucket '{}' lacks versioning and cross-region replication for data durability",
                    bucket_info.name
                ),
                severity: Severity::Medium,
                category: Category::DisasterRecovery,
                resource_type: "S3Bucket".to_string(),
                resource_id: bucket_info.name.clone(),
                region: bucket_info.region.clone(),
                details: json!({
                    "waf_pillar": "Reliability",
                    "waf_question": "REL-09",
                    "gap": "Backup and versioning strategy",
                    "business_risk": "Data loss potential",
                    "recommended_action": "Enable versioning and consider cross-region replication"
                }),
                discovered_at: now,
            });
        }
        
        Ok(findings)
    }

    async fn check_public_access(&self, bucket_name: &str, bucket_info: &mut S3BucketInfo) -> Result<()> {
        // Check bucket ACL
        if let Ok(acl_response) = self.aws_client.s3_client
            .get_bucket_acl()
            .bucket(bucket_name)
            .send()
            .await
        {
            for grant in acl_response.grants() {
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
                let rules = config.rules();
                if !rules.is_empty() {
                    bucket_info.encryption_enabled = true;
                    if let Some(rule) = rules.first() {
                        if let Some(default_encryption) = rule.apply_server_side_encryption_by_default() {
                            bucket_info.encryption_type = default_encryption.sse_algorithm().map(|a| format!("{a:?}"));
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
            for rule in lifecycle_response.rules() {
                let lifecycle_rule = LifecycleRule {
                    id: rule.id().unwrap_or("").to_string(),
                    status: rule.status().as_str().to_string(),
                    filter: rule.filter().and_then(|f| f.prefix()).map(|p| p.to_string()),
                    transitions: rule.transitions().iter().map(|t| LifecycleTransition {
                        days: t.days(),
                        storage_class: t.storage_class().map(|sc| sc.as_str().to_string()).unwrap_or_default(),
                    }).collect(),
                };
                bucket_info.lifecycle_rules.push(lifecycle_rule);
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
                for rule in config.rules() {
                    if let Some(destination) = rule.destination() {
                        let replication_rule = ReplicationRule {
                            id: rule.id().unwrap_or("").to_string(),
                            status: rule.status().as_str().to_string(),
                            destination_bucket: destination.bucket.to_string(),
                            destination_region: destination.storage_class().map(|sc| sc.as_str().to_string()).unwrap_or_default(),
                        };
                        bucket_info.replication_rules.push(replication_rule);
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
        Ok(findings)
    }
}