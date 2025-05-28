use aws_sdk_iam::Client;
use aws_sdk_iam::types::Policy;
use aws_config::SdkConfig;
use crate::ai;
use crate::output::print_findings;
use anyhow::Result;

pub async fn check_iam(config: &SdkConfig, ai_explain: bool) -> Result<()> {
    let client = Client::new(config);

    println!("🔍 Scanning IAM roles and attached policies...");

    let roles = client.list_roles().send().await?;
    let mut findings = vec![];

    for role in roles.roles().unwrap_or(&[]) {
        let role_name = role.role_name().unwrap_or_default().to_string();
        let attached = client
            .list_attached_role_policies()
            .role_name(&role_name)
            .send()
            .await?;

        for policy in attached.attached_policies().unwrap_or(&[]) {
            let policy_arn = policy.policy_arn().unwrap_or_default();
            let policy_resp = client
                .get_policy()
                .policy_arn(policy_arn)
                .send()
                .await?;
            let version = policy_resp
                .policy()
                .and_then(Policy::default_version_id)
                .unwrap_or_default();

            let doc = client
                .get_policy_version()
                .policy_arn(policy_arn)
                .version_id(version)
                .send()
                .await?;

            let policy_str = doc
                .policy_version()
                .and_then(|v| v.document())
                .unwrap_or_default();

            let decoded = urlencoding::decode(policy_str)?.to_string();

            if decoded.contains(r#""Action":"*""#) && decoded.contains(r#""Resource":"*""#) {
                findings.push((role_name.clone(), decoded));
            }
        }
    }

    if findings.is_empty() {
        println!("✅ No overly permissive policies found.");
    } else {
        println!("❗Found {} risky IAM roles:", findings.len());
        print_findings(&findings);

        if ai_explain {
            ai::explain_iam_findings(&findings).await?;
        }
    }

    Ok(())
}
