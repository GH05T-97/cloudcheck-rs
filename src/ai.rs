use async_openai::types::{ChatCompletionRequestMessageArgs, CreateChatCompletionRequestArgs, Role};
use async_openai::Client;
use anyhow::{Result, anyhow};
use crate::types::Finding;

pub async fn generate_ai_report(findings: &[Finding]) -> Result<String> {
    if findings.is_empty() {
        return Ok("✅ No issues found.".to_string());
    }

    // Turn findings into a formatted string for the prompt
    let mut findings_text = String::new();
    for f in findings {
        findings_text.push_str(&format!("- [{}] {}: {}\n", f.service, f.resource, f.issue));
    }

    let prompt = format!(
        "You are a cloud security and DevOps expert. Analyze the following infrastructure findings:\n\n{}\n\nGroup them by category (Security, Performance, Cost, Disaster Recovery). Provide actionable recommendations for each.\nRespond in clear markdown format.",
        findings_text
    );

    let request = CreateChatCompletionRequestArgs::default()
        .model("gpt-4")
        .messages([ChatCompletionRequestMessageArgs::default()
            .role(Role::User)
            .content(prompt)
            .build()?])
        .build()?;

    let client = Client::new();
    let response = client.chat().create(request).await?;
    let output = response.choices.first()
        .ok_or_else(|| anyhow!("No response from AI"))?
        .message
        .content
        .clone()
        .unwrap_or_else(|| "No content returned".to_string());

    Ok(output)
}

pub async fn explain_iam_findings(findings: &[(String, String)]) -> anyhow::Result<()> {
    println!("💬 AI Explanation for IAM findings:");

    for (role, policy_doc) in findings {
        // Replace this with actual OpenAI call later
        println!("- Role `{}` has overly permissive policy.\n  Reason: Full wildcard access detected.\n", role);
    }

    Ok(())
}