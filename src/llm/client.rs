use crate::{
    scanner::types::Finding,
    error::{CloudGuardError, Result},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, debug};

#[derive(Debug, Serialize)]
struct OpenAIRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponse {
    choices: Vec<OpenAIChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    message: OpenAIResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponseMessage {
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAnalysis {
    pub summary: String,
    pub priority_findings: Vec<PriorityFinding>,
    pub recommendations: Vec<Recommendation>,
    pub risk_assessment: RiskAssessment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityFinding {
    pub finding_id: String,
    pub impact: String,
    pub urgency: String,
    pub business_context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub title: String,
    pub description: String,
    pub category: String,
    pub effort: String, // Low, Medium, High
    pub impact: String, // Low, Medium, High
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_risk_level: String,
    pub critical_issues_count: u32,
    pub high_issues_count: u32,
    pub medium_issues_count: u32,
    pub low_issues_count: u32,
    pub compliance_impact: String,
    pub business_impact: String,
}

pub struct LlmClient {
    client: Client,
    api_key: String,
    api_url: String,
}

impl LlmClient {
    pub fn new(api_key: &str) -> Result<Self> {
        if api_key.is_empty() {
            return Err(CloudGuardError::ConfigError(
                "OpenAI API key is required".to_string()
            ));
        }

        Ok(Self {
            client: Client::new(),
            api_key: api_key.to_string(),
            api_url: "https://api.openai.com/v1/chat/completions".to_string(),
        })
    }

    pub async fn analyze_s3_findings(&self, findings: &[Finding]) -> Result<LlmAnalysis> {
        info!("Analyzing {} S3 findings with LLM", findings.len());
        
        let prompt = self.create_s3_analysis_prompt(findings);
        let response = self.call_openai(&prompt).await?;
        
        // Parse the JSON response from the LLM
        let analysis: LlmAnalysis = serde_json::from_str(&response)
            .map_err(|e| CloudGuardError::LlmError(
                format!("Failed to parse LLM response: {}", e)
            ))?;

        debug!("LLM analysis completed successfully");
        Ok(analysis)
    }

    async fn call_openai(&self, prompt: &str) -> Result<String> {
        let request = OpenAIRequest {
            model: "gpt-4".to_string(),
            messages: vec![
                OpenAIMessage {
                    role: "system".to_string(),
                    content: "You are a cloud security expert analyzing AWS S3 bucket configurations. Return your analysis as valid JSON only, with no additional text or markdown.".to_string(),
                },
                OpenAIMessage {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                },
            ],
            max_tokens: 2000,
            temperature: 0.1,
        };

        let response = self.client
            .post(&self.api_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(CloudGuardError::LlmError(
                format!("OpenAI API error: {}", error_text)
            ));
        }

        let openai_response: OpenAIResponse = response.json().await?;
        
        openai_response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| CloudGuardError::LlmError(
                "No response from OpenAI API".to_string()
            ))
    }

    fn create_s3_analysis_prompt(&self, findings: &[Finding]) -> String {
        let findings_json = serde_json::to_string_pretty(findings)
            .unwrap_or_else(|_| "[]".to_string());

        format!(r#"
Analyze the following S3 security findings and provide a comprehensive analysis in JSON format.

S3 Findings:
{}

Please provide your analysis in the following JSON structure:
{{
  "summary": "Brief overview of the security posture",
  "priority_findings": [
    {{
      "finding_id": "UUID of the finding",
      "impact": "Description of potential impact",
      "urgency": "How urgently this should be addressed",
      "business_context": "Business implications"
    }}
  ],
  "recommendations": [
    {{
      "title": "Recommendation title",
      "description": "Detailed description",
      "category": "Security/Cost/Performance/DR",
      "effort": "Low/Medium/High",
      "impact": "Low/Medium/High",
      "steps": ["Step 1", "Step 2", "Step 3"]
    }}
  ],
  "risk_assessment": {{
    "overall_risk_level": "Low/Medium/High/Critical",
    "critical_issues_count": 0,
    "high_issues_count": 0,
    "medium_issues_count": 0,
    "low_issues_count": 0,
    "compliance_impact": "Impact on compliance requirements",
    "business_impact": "Overall business impact assessment"
  }}
}}

Focus on:
1. Security vulnerabilities and their real-world impact
2. Cost optimization opportunities
3. Disaster recovery and business continuity risks
4. Performance implications
5. Compliance considerations (SOC2, PCI-DSS, GDPR, etc.)

Provide actionable, specific recommendations with clear steps.
"#, findings_json)
    }
}