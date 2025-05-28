use aws_sdk_cloudwatch::Client;
use aws_config::SdkConfig;
use crate::ai;
use crate::output::print_findings;
use anyhow::Result;

pub async fn check_events(config: &SdkConfig, ai_explain: bool) -> Result<()> {
    let client = Client::new(config);

    println!("🔍 Scanning EventBridge / CloudWatch rules...");

    // Placeholder for scanning event-driven services
    let mut findings = vec![];

    // TODO: list rules and analyze for security issues or broad targets

    if findings.is_empty() {
        println!("✅ No risky EventBridge rules found.");
    } else {
        println!("❗Potential issues in EventBridge rules:");
        print_findings(&findings);

        if ai_explain {
            ai::explain_event_findings(&findings).await?;
        }
    }

    Ok(())
}
