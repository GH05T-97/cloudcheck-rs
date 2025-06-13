use serde::{Deserialize, Serialize};

/// Enum to specify the type of LLM provider to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LlmProviderType {
    OpenAI,
    GeminiFlash,
    // Add other providers here as needed, e.g., DeepSeek, Cohere, Anthropic
    // DeepSeek,
}

/// Common structure for LLM analysis output.
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

// --- OpenAI Specific Structs ---
#[derive(Debug, Serialize)]
pub struct OpenAICompletionRequest {
    pub model: String,
    pub(crate) messages: Vec<OpenAIMessage>,
    pub(crate) max_tokens: u32,
    pub(crate) temperature: f32,
}

#[derive(Debug, Serialize)]
pub struct OpenAIMessage {
    pub(crate) role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct OpenAICompletionResponse {
    pub choices: Vec<OpenAIChoice>,
}

#[derive(Debug, Deserialize)]
pub struct OpenAIChoice {
    pub message: OpenAIResponseMessage,
}

#[derive(Debug, Deserialize)]
pub struct OpenAIResponseMessage {
    pub content: String,
}

// --- Gemini Specific pub structs ---
#[derive(Debug, Serialize)]
pub struct GeminiGenerateContentRequest {
    pub contents: Vec<GeminiContent>,
    #[serde(rename = "generationConfig", skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GeminiGenerationConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiContent {
    pub role: String,
    pub(crate) parts: Vec<GeminiPart>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GeminiPart {
    pub(crate) text: String,
}

#[derive(Debug, Serialize)]
pub struct GeminiGenerationConfig {
    #[serde(rename = "responseMimeType")]
    pub response_mime_type: String,
    #[serde(rename = "responseSchema")]
    pub response_schema: serde_json::Value, // For pub structured output (JSON schema)
}

#[derive(Debug, Deserialize)]
pub struct GeminiGenerateContentResponse {
    pub candidates: Vec<GeminiCandidate>,
}

#[derive(Debug, Deserialize)]
pub struct GeminiCandidate {
    pub content: GeminiContent,
}
