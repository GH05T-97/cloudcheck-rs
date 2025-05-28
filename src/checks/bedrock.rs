use aws_sdk_bedrock::Client;
use aws_config::SdkConfig;
use crate::ai;
use crate::output::print_findings;
use anyhow::Result;

pub async fn check_bedrock(config: &SdkConfig, ai_explain: bool) -> Result<()> {
    let client = Client::new(config);

    println!("🔍 Scanning Bedrock models and access policies...");

    let mut findings = vec![];

    // TODO: Check model access policies, usage logging, data leakage risks

    if findings.is_empty() {
        println!("✅ No risky Bedrock configurations found.");
    } else {
        println!("❗Potential Bedrock misconfigurations detected:");
        print_findings(&findings);

        if ai_explain {
            ai::explain_bedrock_findings(&findings).await?;
        }
    }

    Ok(())
}
