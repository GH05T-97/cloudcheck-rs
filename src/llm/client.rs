use crate::{
    scanner::types::Finding,
    error::{CloudGuardError, Result},
};
use reqwest::Client;
use serde_json::json; // Needed for building JSON payloads
use tracing::{info, debug};

use crate::llm::structs::{
    OpenAICompletionRequest, OpenAIMessage, OpenAICompletionResponse,
    GeminiGenerateContentRequest, GeminiContent, GeminiPart, GeminiGenerationConfig,
    GeminiGenerateContentResponse, LlmAnalysis, LlmProviderType
};

pub struct LlmClient {
    client: Client,
    api_key: String,
    provider_type: LlmProviderType,
    model_name: String,
}

impl LlmClient {
    /// Creates a new LlmClient configured for a specific provider and model.
    pub fn new(api_key: &str, provider_type: LlmProviderType, model_name: &str) -> Result<Self> {
        if api_key.is_empty() {
            return Err(CloudGuardError::ConfigError(
                "LLM API key is required".to_string()
            ));
        }

        Ok(Self {
            client: Client::new(),
            api_key: api_key.to_string(),
            provider_type,
            model_name: model_name.to_string(),
        })
    }

    /// Analyzes S3 findings using the configured LLM.
    pub async fn analyze_s3_findings(&self, findings: &[Finding]) -> Result<LlmAnalysis> {
        info!("Analyzing {} S3 findings with LLM ({:?}, model: {})", 
            findings.len(), self.provider_type, self.model_name);
        
        let prompt = self.create_s3_analysis_prompt(findings);
        let response_content = self.call_llm(&prompt).await?;
        
        // Parse the JSON response from the LLM
        let analysis: LlmAnalysis = serde_json::from_str(&response_content)
            .map_err(|e| CloudGuardError::LlmError(
                format!("Failed to parse LLM response: {} (Response: {})", e, response_content)
            ))?;

        debug!("LLM analysis completed successfully");
        Ok(analysis)
    }

    /// Makes the actual API call to the configured LLM.
    async fn call_llm(&self, prompt: &str) -> Result<String> {
        let (url, request_body) = match self.provider_type {
            LlmProviderType::OpenAI => {
                let request = OpenAICompletionRequest {
                    model: self.model_name.clone(),
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
                ("https://api.openai.com/v1/chat/completions".to_string(), serde_json::to_value(&request)?)
            }
            LlmProviderType::GeminiFlash => {
                let request = GeminiGenerateContentRequest {
                    contents: vec![
                        GeminiContent {
                            role: "user".to_string(),
                            parts: vec![
                                GeminiPart {
                                    text: "You are a cloud security expert analyzing AWS S3 bucket configurations. Return your analysis as valid JSON only, with no additional text or markdown.".to_string(),
                                },
                                GeminiPart {
                                    text: prompt.to_string(),
                                },
                            ],
                        },
                    ],
                    // Explicitly ask for JSON output using responseSchema for Gemini
                    generation_config: Some(GeminiGenerationConfig {
                        response_mime_type: "application/json".to_string(),
                        response_schema: json!({
                            "type": "OBJECT",
                            "properties": {
                                "summary": { "type": "STRING" },
                                "priority_findings": {
                                    "type": "ARRAY",
                                    "items": {
                                        "type": "OBJECT",
                                        "properties": {
                                            "finding_id": { "type": "STRING" },
                                            "impact": { "type": "STRING" },
                                            "urgency": { "type": "STRING" },
                                            "business_context": { "type": "STRING" }
                                        }
                                    }
                                },
                                "recommendations": {
                                    "type": "ARRAY",
                                    "items": {
                                        "type": "OBJECT",
                                        "properties": {
                                            "title": { "type": "STRING" },
                                            "description": { "type": "STRING" },
                                            "category": { "type": "STRING" },
                                            "effort": { "type": "STRING" },
                                            "impact": { "type": "STRING" },
                                            "steps": { "type": "ARRAY", "items": { "type": "STRING" } }
                                        }
                                    }
                                },
                                "risk_assessment": {
                                    "type": "OBJECT",
                                    "properties": {
                                        "overall_risk_level": { "type": "STRING" },
                                        "critical_issues_count": { "type": "NUMBER" },
                                        "high_issues_count": { "type": "NUMBER" },
                                        "medium_issues_count": { "type": "NUMBER" },
                                        "low_issues_count": { "type": "NUMBER" },
                                        "compliance_impact": { "type": "STRING" },
                                        "business_impact": { "type": "STRING" }
                                    }
                                }
                            }
                        }),
                    }),
                };
                (
                    format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", 
                            self.model_name, self.api_key), // Gemini API key in URL param
                    serde_json::to_value(&request)?
                )
            }
            // LlmProviderType::DeepSeek => {
            //     // Placeholder for DeepSeek
            //     // You would define DeepSeek specific request/response structs and API logic here.
            //     // Example (hypothetical, based on common patterns):
            //     // let request = DeepSeekCompletionRequest { ... };
            //     // ("https://api.deepseek.com/v1/chat/completions".to_string(), serde_json::to_value(&request)?)
            //     return Err(CloudGuardError::LlmError("DeepSeek integration not yet implemented.".to_string()));
            // }
        };

        let request_builder = self.client
            .post(&url)
            .json(&request_body);
        
        // OpenAI uses "Authorization: Bearer KEY", Gemini uses "?key=KEY" in URL
        let response = match self.provider_type {
            LlmProviderType::OpenAI => {
                request_builder
                    .header("Authorization", format!("Bearer {}", self.api_key))
                    .header("Content-Type", "application/json") // Explicitly set for clarity
                    .send()
                    .await?
            }
            LlmProviderType::GeminiFlash => {
                // Gemini key is already in the URL for this version
                request_builder
                    .header("Content-Type", "application/json") // Explicitly set for clarity
                    .send()
                    .await?
            }
            // LlmProviderType::DeepSeek => { ... }
        };


        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(CloudGuardError::LlmError(
                format!("LLM API error (Status: {}): {}", status, error_text)
            ));
        }

        let response_body: serde_json::Value = response.json().await?;
        debug!("LLM API raw response: {}", response_body);

        let extracted_content = match self.provider_type {
            LlmProviderType::OpenAI => {
                let openai_response: OpenAICompletionResponse = serde_json::from_value(response_body)
                    .map_err(|e| CloudGuardError::LlmError(format!("Failed to parse OpenAI response: {}", e)))?;
                openai_response
                    .choices
                    .first()
                    .map(|choice| choice.message.content.clone())
                    .ok_or_else(|| CloudGuardError::LlmError("No content in OpenAI response".to_string()))?
            }
            LlmProviderType::GeminiFlash => {
                let gemini_response: GeminiGenerateContentResponse = serde_json::from_value(response_body)
                    .map_err(|e| CloudGuardError::LlmError(format!("Failed to parse Gemini response: {}", e)))?;
                gemini_response
                    .candidates
                    .first()
                    .map(|candidate| candidate.content.parts.first().map(|part| part.text.clone()))
                    .flatten() // Flatten Option<Option<String>> to Option<String>
                    .ok_or_else(|| CloudGuardError::LlmError("No content in Gemini response".to_string()))?
            }
            // LlmProviderType::DeepSeek => { ... }
        };
        
        Ok(extracted_content)
    }

    /// Creates a standardized prompt for S3 analysis.
    fn create_s3_analysis_prompt(&self, findings: &[Finding]) -> String {
        let findings_json = serde_json::to_string_pretty(findings)
            .unwrap_or_else(|_| "[]".to_string());

        format!(r#"
Analyze the following S3 security findings and provide a comprehensive analysis in JSON format.
Ensure the output is strictly valid JSON conforming to the specified schema, with no surrounding text or markdown.

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
