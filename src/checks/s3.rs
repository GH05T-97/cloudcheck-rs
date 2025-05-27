use aws_sdk_s3::Client;
use aws_config::SdkConfig;
use crate::output::print_findings;
use anyhow::Result;

pub async fn check_s3(config: &SdkConfig, _ai_explain: bool) -> Result<()> {
    let client = Client::new(config);

    println!("🔍 Scanning S3 buckets for public access...");

    let buckets = client.list_buckets().send().await?;
    let mut findings = vec![];

    for bucket in buckets.buckets().unwrap_or(&[]) {
        let name = bucket.name().unwrap_or_default();

        // Check bucket ACL
        let acl = client.get_bucket_acl().bucket(name).send().await?;
        for grant in acl.grants().unwrap_or(&[]) {
            if let Some(grantee) = grant.grantee() {
                if let Some(uri) = grantee.uri() {
                    if uri.contains("AllUsers") || uri.contains("AuthenticatedUsers") {
                        findings.push((name.to_string(), "Public ACL".to_string()));
                    }
                }
            }
        }

        // Check bucket policy
        let policy_status = client.get_bucket_policy_status().bucket(name).send().await;
        if let Ok(status) = policy_status {
            if let Some(is_public) = status.policy_status().and_then(|s| Some(s.is_public())) {
                if is_public {
                    findings.push((name.to_string(), "Public policy".to_string()));
                }
            }
        }

        let encryption = client.get_bucket_encryption().bucket(name).send().await;
        if encryption.is_err() {
            findings.push((name.to_string(), "No default encryption".to_string()));
        }

    }

    if findings.is_empty() {
        println!("✅ No publicly accessible S3 buckets found.");
    } else {
        println!("❗Public S3 buckets detected:");
        print_findings(&findings);
    }

    Ok(())
}
