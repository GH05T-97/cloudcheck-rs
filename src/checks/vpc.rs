use aws_sdk_ec2::Client;
use aws_config::SdkConfig;
use crate::ai;
use crate::output::print_findings;
use anyhow::Result;

// pub async fn check_vpc(config: &SdkConfig, ai_explain: bool) -> Result<()> {
//     let client = Client::new(config);

//     println!("🔍 Scanning VPC configurations for security risks...");

//     let mut findings = vec![];

//     // TODO: Check for open security groups, misconfigured route tables, exposed subnets

//     if findings.is_empty() {
//         println!("✅ No VPC misconfigurations found.");
//     } else {
//         println!("❗VPC security issues detected:");
//         print_findings(&findings);

//         if ai_explain {
//             ai::explain_vpc_findings(&findings).await?;
//         }
//     }

//     Ok(())
// }
