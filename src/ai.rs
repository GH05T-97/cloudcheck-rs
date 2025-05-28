use async_openai::types::{ChatCompletionRequestMessageArgs, CreateChatCompletionRequestArgs, Role};
use async_openai::Client;
use anyhow::{Result, anyhow};
use crate::types::Finding;


pub async fn explain_iam_findings(findings: &[(String, String)]) -> anyhow::Result<()> {
    println!("💬 AI Explanation for IAM findings:");

    for (role, policy_doc) in findings {
        // Replace this with actual OpenAI call later
        println!("- Role `{}` has overly permissive policy.\n  Reason: Full wildcard access detected.\n", role);
    }

    Ok(())
}