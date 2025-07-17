use crate::{
    aws::AwsClient,
    scanner::types::*,
    error::{CloudGuardError, Result},
};
use aws_sdk_iam::types::{User, Role, Group, Policy};
use chrono::Utc;
use serde_json::json;
use tracing::{info, debug};
use uuid::Uuid;

pub struct IamScanner {
    aws_client: AwsClient,
}

impl IamScanner {
    pub fn new(aws_client: AwsClient) -> Self {
        Self { aws_client }
    }

    pub async fn scan(&self) -> Result<Vec<Finding>> {
        info!("Starting IAM scan");
        let mut findings = Vec::new();
        
        // Create IAM client
        let iam_client = aws_sdk_iam::Client::new(&aws_config::defaults(aws_config::BehaviorVersion::latest()).load().await);
        
        // Scan users
        let user_findings = self.scan_users(&iam_client).await?;
        findings.extend(user_findings);
        
        // Scan roles
        let role_findings = self.scan_roles(&iam_client).await?;
        findings.extend(role_findings);
        
        // Scan groups
        let group_findings = self.scan_groups(&iam_client).await?;
        findings.extend(group_findings);
        
        // Scan policies
        let policy_findings = self.scan_policies(&iam_client).await?;
        findings.extend(policy_findings);
        
        // Scan account-level settings
        let account_findings = self.scan_account_settings(&iam_client).await?;
        findings.extend(account_findings);

        info!("IAM scan completed with {} findings", findings.len());
        Ok(findings)
    }

    async fn scan_users(&self, iam_client: &aws_sdk_iam::Client) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        info!("Scanning IAM users");
        
        let users_response = iam_client.list_users().send().await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?;
            
        for user in users_response.users() {
            let user_name = user.user_name();
            debug!("Scanning user: {}", user_name);
            
            let user_info = self.analyze_user(iam_client, user).await?;
            let user_findings = self.generate_user_findings(&user_info).await?;
            findings.extend(user_findings);
        }
        
        Ok(findings)
    }

    async fn scan_roles(&self, iam_client: &aws_sdk_iam::Client) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        info!("Scanning IAM roles");
        
        let roles_response = iam_client.list_roles().send().await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?;
            
        for role in roles_response.roles() {
            let role_name = role.role_name();
            debug!("Scanning role: {}", role_name);
            
            let role_info = self.analyze_role(iam_client, role).await?;
            let role_findings = self.generate_role_findings(&role_info).await?;
            findings.extend(role_findings);
        }
        
        Ok(findings)
    }

    async fn scan_groups(&self, iam_client: &aws_sdk_iam::Client) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        info!("Scanning IAM groups");
        
        let groups_response = iam_client.list_groups().send().await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?;
            
        for group in groups_response.groups() {
            let group_name = group.group_name();
            debug!("Scanning group: {}", group_name);
            
            let group_info = self.analyze_group(iam_client, group).await?;
            let group_findings = self.generate_group_findings(&group_info).await?;
            findings.extend(group_findings);
        }
        
        Ok(findings)
    }

    async fn scan_policies(&self, iam_client: &aws_sdk_iam::Client) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        info!("Scanning IAM policies");
        
        // Scan customer-managed policies only (skip AWS managed)
        let policies_response = iam_client
            .list_policies()
            .scope(aws_sdk_iam::types::PolicyScopeType::Local)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?;
            
        for policy in policies_response.policies() {
            let policy_name = policy.policy_name();
            debug!("Scanning policy: {:?}", policy_name);
            
            let policy_info = self.analyze_policy(iam_client, policy).await?;
            let policy_findings = self.generate_policy_findings(&policy_info).await?;
            findings.extend(policy_findings);
        }
        
        Ok(findings)
    }

    async fn scan_account_settings(&self, iam_client: &aws_sdk_iam::Client) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();
        
        info!("Scanning account-level IAM settings");
        
        // Check password policy
        match iam_client.get_account_password_policy().send().await {
            Ok(policy_response) => {
                if let Some(policy) = policy_response.password_policy() {
                    let password_findings = self.analyze_password_policy(policy).await?;
                    findings.extend(password_findings);
                }
            },
            Err(_) => {
                // No password policy set
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "WAF SEC-02: No Account Password Policy".to_string(),
                    description: "AWS account does not have a password policy configured".to_string(),
                    severity: Severity::High,
                    category: Category::Security,
                    resource_type: "IAMAccount".to_string(),
                    resource_id: "account-password-policy".to_string(),
                    region: self.aws_client.region.clone(),
                    details: json!({
                        "waf_pillar": "Security",
                        "waf_question": "SEC-02",
                        "compliance_gap": "Password policy missing",
                        "recommended_action": "Configure account password policy"
                    }),
                    discovered_at: now,
                });
            }
        }
        
        // Check for root access key usage
        let account_summary = iam_client.get_account_summary().send().await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?;
            
        if let Some(summary_map) = account_summary.summary_map() {
            if let Some(access_keys) = summary_map.get(&aws_sdk_iam::types::SummaryKeyType::AccountAccessKeysPresent) {
                if *access_keys > 0 {
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        title: "WAF SEC-02: Root Access Keys Present".to_string(),
                        description: "AWS root account has access keys configured".to_string(),
                        severity: Severity::Critical,
                        category: Category::Security,
                        resource_type: "IAMAccount".to_string(),
                        resource_id: "root-access-keys".to_string(),
                        region: self.aws_client.region.clone(),
                        details: json!({
                            "waf_pillar": "Security",
                            "waf_question": "SEC-02",
                            "compliance_gap": "Root access keys present",
                            "security_risk": "Unlimited access potential",
                            "recommended_action": "Remove root access keys and use IAM users/roles"
                        }),
                        discovered_at: now,
                    });
                }
            }
        }
        
        Ok(findings)
    }

    async fn analyze_user(&self, iam_client: &aws_sdk_iam::Client, user: &User) -> Result<IamUserInfo> {
        let user_name = user.user_name();
        
        // Get user policies
        let attached_policies = iam_client
            .list_attached_user_policies()
            .user_name(user_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .attached_policies()
            .to_vec();
            
        let inline_policies = iam_client
            .list_user_policies()
            .user_name(user_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .policy_names()
            .to_vec();
            
        // Get user groups
        let groups = iam_client
            .list_groups_for_user()
            .user_name(user_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .groups()
            .to_vec();
            
        // Get access keys
        let access_keys = iam_client
            .list_access_keys()
            .user_name(user_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .access_key_metadata()
            .to_vec();
            
        // Check MFA devices
        let mfa_devices = iam_client
            .list_mfa_devices()
            .user_name(user_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .mfa_devices()
            .to_vec();

        Ok(IamUserInfo {
            user_name: user_name.to_string(),
            user_id: user.user_id().to_string(),
            arn: user.arn().to_string(),
            path: user.path().to_string(),
            create_date: user.create_date().map(|d| {
                chrono::DateTime::from_timestamp(d.secs(), 0).unwrap_or_else(|| Utc::now())
            }),
            password_last_used: user.password_last_used().map(|d| chrono::DateTime::from_timestamp(d.secs(), 0).unwrap_or_default()),
            attached_policies: attached_policies.into_iter().map(|p| p.policy_name().unwrap_or_default().to_string()).collect(),
            inline_policies: inline_policies.into_iter().map(|p| p.to_string()).collect(),
            groups: groups.into_iter().map(|g| g.group_name().to_string()).collect(),
            access_keys_count: access_keys.len() as u32,
            has_mfa: !mfa_devices.is_empty(),
            console_access: user.password_last_used().is_some() || user.user_name().contains("console"),
            tags: user.tags().iter().map(|t| (t.key().to_string(), t.value().to_string())).collect(),
        })
    }

    async fn analyze_role(&self, iam_client: &aws_sdk_iam::Client, role: &Role) -> Result<IamRoleInfo> {
        let role_name = role.role_name();
        
        // Get role policies
        let attached_policies = iam_client
            .list_attached_role_policies()
            .role_name(role_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .attached_policies()
            .to_vec();
            
        let inline_policies = iam_client
            .list_role_policies()
            .role_name(role_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .policy_names()
            .to_vec();

        Ok(IamRoleInfo {
            role_name: role_name.to_string(),
            role_id: role.role_id().to_string(),
            arn: role.arn().to_string(),
            path: role.path().to_string(),
            create_date: role.create_date().map(|d| {
                chrono::DateTime::from_timestamp(d.secs(), 0).unwrap_or_else(|| Utc::now())
            }),
            assume_role_policy_document: role.assume_role_policy_document().map(|p| p.to_string()),
            description: role.description().map(|d| d.to_string()),
            max_session_duration: role.max_session_duration(),
            attached_policies: attached_policies.into_iter().map(|p| p.policy_name().unwrap_or_default().to_string()).collect(),
            inline_policies: inline_policies.into_iter().map(|p| p.to_string()).collect(),
            tags: role.tags().iter().map(|t| (t.key().to_string(), t.value().to_string())).collect(),
        })
    }

    async fn analyze_group(&self, iam_client: &aws_sdk_iam::Client, group: &Group) -> Result<IamGroupInfo> {
        let group_name = group.group_name();
        
        // Get group policies
        let attached_policies = iam_client
            .list_attached_group_policies()
            .group_name(group_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .attached_policies()
            .to_vec();
            
        let inline_policies = iam_client
            .list_group_policies()
            .group_name(group_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .policy_names()
            .to_vec();
            
        // Get group members
        let users = iam_client
            .get_group()
            .group_name(group_name)
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?
            .users()
            .to_vec();

        Ok(IamGroupInfo {
            group_name: group_name.to_string(),
            group_id: group.group_id().to_string(),
            arn: group.arn().to_string(),
            path: group.path().to_string(),
            create_date: group.create_date().map(|d| {
                chrono::DateTime::from_timestamp(d.secs(), 0).unwrap_or_else(|| Utc::now())
            }),
            attached_policies: attached_policies.into_iter().map(|p| p.policy_name().unwrap_or_default().to_string()).collect(),
            inline_policies: inline_policies.into_iter().map(|p| p.to_string()).collect(),
            users: users.into_iter().map(|u| u.user_name().to_string()).collect(),
        })
    }

    async fn analyze_policy(&self, iam_client: &aws_sdk_iam::Client, policy: &Policy) -> Result<IamPolicyInfo> {
        let policy_arn = policy.arn();
        
        // Get policy version
        let policy_version = iam_client
            .get_policy_version()
            .policy_arn(policy_arn.unwrap_or_default())
            .version_id(policy.default_version_id().unwrap_or_default())
            .send()
            .await
            .map_err(|e| CloudGuardError::AwsError(e.to_string()))?;
            
        let policy_document = policy_version.policy_version()
            .and_then(|v| v.document())
            .map(|d| d.to_string());

        Ok(IamPolicyInfo {
            policy_name: policy.policy_name().unwrap_or_default().to_string(),
            policy_id: policy.policy_id().unwrap_or_default().to_string(),
            arn: policy_arn.unwrap_or_default().to_string(),
            path: policy.path().unwrap_or_default().to_string(),
            default_version_id: policy.default_version_id().unwrap_or_default().to_string(),
            attachment_count: policy.attachment_count().unwrap_or(0),
            permissions_boundary_usage_count: policy.permissions_boundary_usage_count().unwrap_or(0),
            is_attachable: policy.is_attachable(),
            description: policy.description().map(|d| d.to_string()),
            create_date: policy.create_date().map(|d| chrono::DateTime::from_timestamp(d.secs(), 0).unwrap_or_default()),
            update_date: policy.update_date().map(|d| chrono::DateTime::from_timestamp(d.secs(), 0).unwrap_or_default()),
            policy_document,
            tags: policy.tags().iter().map(|t| (t.key().to_string(), t.value().to_string())).collect(),
        })
    }

    async fn analyze_password_policy(&self, policy: &aws_sdk_iam::types::PasswordPolicy) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();
        
        // Check minimum password length
        if policy.minimum_password_length() < Some(14) {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF SEC-02: Weak Password Length Requirement".to_string(),
                description: format!(
                    "Password policy requires only {} characters (recommended: 14+)",
                    policy.minimum_password_length().unwrap_or(0)
                ),
                severity: Severity::Medium,
                category: Category::Security,
                resource_type: "IAMPasswordPolicy".to_string(),
                resource_id: "password-policy".to_string(),
                region: self.aws_client.region.clone(),
                details: json!({
                    "current_length": policy.minimum_password_length(),
                    "recommended_length": 14,
                    "waf_pillar": "Security"
                }),
                discovered_at: now,
            });
        }
        
        // Check password expiration
        if !policy.require_numbers() || !policy.require_symbols() || !policy.require_uppercase_characters() || !policy.require_lowercase_characters() {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF SEC-02: Insufficient Password Complexity".to_string(),
                description: "Password policy does not require all character types".to_string(),
                severity: Severity::Medium,
                category: Category::Security,
                resource_type: "IAMPasswordPolicy".to_string(),
                resource_id: "password-policy".to_string(),
                region: self.aws_client.region.clone(),
                details: json!({
                    "require_numbers": policy.require_numbers(),
                    "require_symbols": policy.require_symbols(),
                    "require_uppercase": policy.require_uppercase_characters(),
                    "require_lowercase": policy.require_lowercase_characters(),
                    "waf_pillar": "Security"
                }),
                discovered_at: now,
            });
        }
        
        Ok(findings)
    }

    async fn generate_user_findings(&self, user_info: &IamUserInfo) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();
        
        // Check for users without MFA
        if user_info.console_access && !user_info.has_mfa {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF SEC-02: Console User Without MFA".to_string(),
                description: format!("User '{}' has console access but no MFA configured", user_info.user_name),
                severity: Severity::High,
                category: Category::Security,
                resource_type: "IAMUser".to_string(),
                resource_id: user_info.user_name.clone(),
                region: self.aws_client.region.clone(),
                details: json!({
                    "has_console_access": user_info.console_access,
                    "has_mfa": user_info.has_mfa,
                    "waf_pillar": "Security",
                    "waf_question": "SEC-02"
                }),
                discovered_at: now,
            });
        }
        
        // Check for users with multiple access keys
        if user_info.access_keys_count > 1 {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "WAF SEC-02: Multiple Access Keys".to_string(),
                description: format!("User '{}' has {} access keys (recommended: 1)", 
                    user_info.user_name, user_info.access_keys_count),
                severity: Severity::Medium,
                category: Category::Security,
                resource_type: "IAMUser".to_string(),
                resource_id: user_info.user_name.clone(),
                region: self.aws_client.region.clone(),
                details: json!({
                    "access_keys_count": user_info.access_keys_count,
                    "waf_pillar": "Security"
                }),
                discovered_at: now,
            });
        }
        
        // Check for overly permissive policies
        for policy_name in &user_info.attached_policies {
            if policy_name.contains("Admin") || policy_name == "PowerUserAccess" {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "WAF SEC-03: Overly Permissive User Policy".to_string(),
                    description: format!("User '{}' has admin-level policy '{}' attached", 
                        user_info.user_name, policy_name),
                    severity: Severity::High,
                    category: Category::Security,
                    resource_type: "IAMUser".to_string(),
                    resource_id: user_info.user_name.clone(),
                    region: self.aws_client.region.clone(),
                    details: json!({
                        "policy_name": policy_name,
                        "waf_pillar": "Security",
                        "waf_question": "SEC-03"
                    }),
                    discovered_at: now,
                });
            }
        }
        
        Ok(findings)
    }

    async fn generate_role_findings(&self, role_info: &IamRoleInfo) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();
        
        // Check for overly permissive assume role policies
        if let Some(assume_policy) = &role_info.assume_role_policy_document {
            if assume_policy.contains("\"*\"") && assume_policy.contains("\"Principal\"") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "WAF SEC-03: Overly Permissive Assume Role Policy".to_string(),
                    description: format!("Role '{}' allows any principal to assume it", role_info.role_name),
                    severity: Severity::Critical,
                    category: Category::Security,
                    resource_type: "IAMRole".to_string(),
                    resource_id: role_info.role_name.clone(),
                    region: self.aws_client.region.clone(),
                    details: json!({
                        "assume_role_policy": assume_policy,
                        "waf_pillar": "Security",
                        "waf_question": "SEC-03"
                    }),
                    discovered_at: now,
                });
            }
        }
        
        // Check for admin policies on roles
        for policy_name in &role_info.attached_policies {
            if policy_name.contains("Admin") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "WAF SEC-03: Admin Policy on Role".to_string(),
                    description: format!("Role '{}' has admin policy '{}' attached", 
                        role_info.role_name, policy_name),
                    severity: Severity::High,
                    category: Category::Security,
                    resource_type: "IAMRole".to_string(),
                    resource_id: role_info.role_name.clone(),
                    region: self.aws_client.region.clone(),
                    details: json!({
                        "policy_name": policy_name,
                        "waf_pillar": "Security"
                    }),
                    discovered_at: now,
                });
            }
        }
        
        Ok(findings)
    }

    async fn generate_group_findings(&self, group_info: &IamGroupInfo) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();
        
        // Check for empty groups
        if group_info.users.is_empty() {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "COST-01: Unused IAM Group".to_string(),
                description: format!("Group '{}' has no members", group_info.group_name),
                severity: Severity::Low,
                category: Category::CostOptimization,
                resource_type: "IAMGroup".to_string(),
                resource_id: group_info.group_name.clone(),
                region: self.aws_client.region.clone(),
                details: json!({
                    "member_count": group_info.users.len(),
                    "waf_pillar": "Cost Optimization"
                }),
                discovered_at: now,
            });
        }
        
        Ok(findings)
    }

    async fn generate_policy_findings(&self, policy_info: &IamPolicyInfo) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let now = Utc::now();
        
        // Check for unused policies
        if policy_info.attachment_count == 0 {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                title: "COST-01: Unused IAM Policy".to_string(),
                description: format!("Policy '{}' is not attached to any users, groups, or roles", 
                    policy_info.policy_name),
                severity: Severity::Low,
                category: Category::CostOptimization,
                resource_type: "IAMPolicy".to_string(),
                resource_id: policy_info.policy_name.clone(),
                region: self.aws_client.region.clone(),
                details: json!({
                    "attachment_count": policy_info.attachment_count,
                    "waf_pillar": "Cost Optimization"
                }),
                discovered_at: now,
            });
        }
        
        // Check for overly broad policies
        if let Some(policy_doc) = &policy_info.policy_document {
            if policy_doc.contains("\"*\"") && policy_doc.contains("\"Resource\"") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "WAF SEC-03: Overly Broad Policy Resources".to_string(),
                    description: format!("Policy '{}' grants access to all resources (*)", 
                        policy_info.policy_name),
                    severity: Severity::Medium,
                    category: Category::Security,
                    resource_type: "IAMPolicy".to_string(),
                    resource_id: policy_info.policy_name.clone(),
                    region: self.aws_client.region.clone(),
                    details: json!({
                        "has_wildcard_resources": true,
                        "waf_pillar": "Security",
                        "waf_question": "SEC-03"
                    }),
                    discovered_at: now,
                });
            }
            
            if policy_doc.contains("\"*\"") && policy_doc.contains("\"Action\"") {
                findings.push(Finding {
                    id: Uuid::new_v4().to_string(),
                    title: "WAF SEC-03: Overly Broad Policy Actions".to_string(),
                    description: format!("Policy '{}' grants all actions (*)", 
                        policy_info.policy_name),
                    severity: Severity::High,
                    category: Category::Security,
                    resource_type: "IAMPolicy".to_string(),
                    resource_id: policy_info.policy_name.clone(),
                    region: self.aws_client.region.clone(),
                    details: json!({
                        "has_wildcard_actions": true,
                        "waf_pillar": "Security",
                        "waf_question": "SEC-03"
                    }),
                    discovered_at: now,
                });
            }
        }
        
        Ok(findings)
    }
}