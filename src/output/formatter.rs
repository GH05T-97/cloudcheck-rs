use crate::{
    error::Result,
    llm::structs::{PriorityFinding, Recommendation, RiskAssessment, LlmAnalysis},
    scanner::types::{Finding, Severity, Category}
};
use colored::*;
use tabled::{Table, Tabled};

pub struct ReportFormatter;

#[derive(Tabled)]
struct FindingRow {
    severity: String,
    category: String,
    title: String,
    resource: String,
    region: String,
}

impl ReportFormatter {
    pub fn new() -> Self {
        Self
    }

    pub async fn display_s3_report(&self, findings: &[Finding], analysis: &LlmAnalysis) -> Result<()> {
        self.print_header();
        self.print_summary(findings, analysis);
        self.print_priority_findings(&analysis.priority_findings, findings);
        self.print_findings_table(findings);
        self.print_recommendations(&analysis.recommendations);
        self.print_risk_assessment(analysis.risk_assessment.clone());
        
        Ok(())
    }

    fn print_header(&self) {
        println!("{}", "CloudGuard S3 Security Scan Report".bright_blue().bold());
        println!("{}", "=".repeat(50));
        println!();
    }

    fn print_summary(&self, findings: &[Finding], analysis: &LlmAnalysis) {
        println!("{}", "Executive Summary".bright_yellow().bold());
        println!("{}", "-".repeat(20));
        println!("{}", analysis.summary);
        println!();

        let (critical, high, medium, low) = self.count_findings_by_severity(findings);
        
        println!("{}", "Findings Overview".bright_cyan().bold());
        println!("{}", "-".repeat(20));
        println!("🔴 Critical: {}", critical.to_string().red().bold());
        println!("🟠 High:     {}", high.to_string().bright_red());
        println!("🟡 Medium:   {}", medium.to_string().yellow());
        println!("🟢 Low:      {}", low.to_string().green());
        println!("📊 Total:    {}", findings.len().to_string().bright_white().bold());
        println!();
    }

    fn print_priority_findings(&self, priority_findings: &[PriorityFinding], all_findings: &[Finding]) {
        if priority_findings.is_empty() {
            return;
        }

        println!("{}", "Priority Findings".bright_red().bold());
        println!("{}", "-".repeat(20));
        
        for (i, pf) in priority_findings.iter().enumerate() {
            if let Some(finding) = all_findings.iter().find(|f| f.id == pf.finding_id) {
                println!("{}. {} {}", 
                    (i + 1).to_string().bright_white().bold(),
                    self.severity_icon(&finding.severity),
                    finding.title.bright_white().bold()
                );
                println!("   💥 Impact: {}", pf.impact.bright_red());
                println!("   ⏰ Urgency: {}", pf.urgency.bright_yellow());
                println!("   🏢 Business Context: {}", pf.business_context);
                println!();
            }
        }
    }

    fn print_findings_table(&self, findings: &[Finding]) {
        if findings.is_empty() {
            println!("{}", "✅ No security issues found!".bright_green().bold());
            return;
        }

        println!("{}", "All Findings".bright_blue().bold());
        println!("{}", "-".repeat(20));

        let rows: Vec<FindingRow> = findings.iter().map(|finding| {
            FindingRow {
                severity: format!("{} {}", 
                    self.severity_icon(&finding.severity),
                    format!("{:?}", finding.severity)
                ),
                category: format!("{:?}", finding.category),
                title: finding.title.clone(),
                resource: finding.resource_id.clone(),
                region: finding.region.clone(),
            }
        }).collect();

        let table = Table::new(rows);
        println!("{}", table);
        println!();
    }

    fn print_recommendations(&self, recommendations: &[Recommendation]) {
        if recommendations.is_empty() {
            return;
        }

        println!("{}", "Recommendations".bright_green().bold());
        println!("{}", "-".repeat(20));

        for (i, rec) in recommendations.iter().enumerate() {
            println!("{}. {} {}", 
                (i + 1).to_string().bright_white().bold(),
                self.category_icon(&rec.category),
                rec.title.bright_white().bold()
            );
            println!("   📝 {}", rec.description);
            println!("   🏗️  Effort: {} | 📈 Impact: {}", 
                self.format_effort(&rec.effort),
                self.format_impact(&rec.impact)
            );
            
            if !rec.steps.is_empty() {
                println!("   📋 Steps:");
                for (step_i, step) in rec.steps.iter().enumerate() {
                    println!("      {}. {}", step_i + 1, step);
                }
            }
            println!();
        }
    }

    fn print_risk_assessment(&self, risk: RiskAssessment) {
        println!("{}", "Risk Assessment".bright_magenta().bold());
        println!("{}", "-".repeat(20));
        
        let risk_color = match risk.overall_risk_level.as_str() {
            "Critical" => "red",
            "High" => "bright_red", 
            "Medium" => "yellow",
            "Low" => "green",
            _ => "white"
        };
        
        println!("🎯 Overall Risk Level: {}", 
            risk.overall_risk_level.color(risk_color).bold()
        );
        println!("📊 Issue Breakdown:");
        println!("   🔴 Critical: {}", risk.critical_issues_count);
        println!("   🟠 High: {}", risk.high_issues_count);
        println!("   🟡 Medium: {}", risk.medium_issues_count);
        println!("   🟢 Low: {}", risk.low_issues_count);
        println!();
        println!("📋 Compliance Impact: {}", risk.compliance_impact);
        println!("💼 Business Impact: {}", risk.business_impact);
        println!();
    }

    fn count_findings_by_severity(&self, findings: &[Finding]) -> (usize, usize, usize, usize) {
        let critical = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count();
        let high = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count();
        let medium = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count();
        let low = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count();
        
        (critical, high, medium, low)
    }

    fn severity_icon(&self, severity: &Severity) -> &str {
        match severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Info => "🔵",
        }
    }

    fn category_icon(&self, category: &str) -> &str {
        match category {
            "Security" => "🔒",
            "CostOptimization" => "💰",
            "Performance" => "⚡",
            "DisasterRecovery" => "🔄",
            "Compliance" => "📋",
            _ => "📌",
        }
    }

    fn format_effort(&self, effort: &str) -> ColoredString {
        match effort {
            "Low" => effort.green(),
            "Medium" => effort.yellow(),
            "High" => effort.red(),
            _ => effort.white(),
        }
    }

    fn format_impact(&self, impact: &str) -> ColoredString {
        match impact {
            "Low" => impact.green(),
            "Medium" => impact.yellow(), 
            "High" => impact.bright_green().bold(),
            _ => impact.white(),
        }
    }


     pub async fn display_iam_report(&self, findings: &[Finding], analysis: &LlmAnalysis) -> Result<()> {
        self.print_iam_header();
        self.print_iam_summary(findings, analysis);
        self.print_priority_findings(&analysis.priority_findings, findings);
        self.print_iam_findings_table(findings);
        self.print_iam_recommendations(&analysis.recommendations);
        self.print_risk_assessment(analysis.risk_assessment.clone());
        
        Ok(())
    }

    fn print_iam_header(&self) {
        println!("{}", "CloudGuard IAM Security Scan Report".bright_blue().bold());
        println!("{}", "=".repeat(50));
        println!();
    }

    fn print_iam_summary(&self, findings: &[Finding], analysis: &LlmAnalysis) {
        println!("{}", "Executive Summary".bright_yellow().bold());
        println!("{}", "-".repeat(20));
        println!("{}", analysis.summary);
        println!();

        let (critical, high, medium, low) = self.count_findings_by_severity(findings);
        
        println!("{}", "IAM Security Overview".bright_cyan().bold());
        println!("{}", "-".repeat(20));
        println!("🔴 Critical: {}", critical.to_string().red().bold());
        println!("🟠 High:     {}", high.to_string().bright_red());
        println!("🟡 Medium:   {}", medium.to_string().yellow());
        println!("🟢 Low:      {}", low.to_string().green());
        println!("📊 Total:    {}", findings.len().to_string().bright_white().bold());
        
        // IAM-specific summary
        let security_findings = findings.iter().filter(|f| matches!(f.category, Category::Security)).count();
        let cost_findings = findings.iter().filter(|f| matches!(f.category, Category::CostOptimization)).count();
        let compliance_findings = findings.iter().filter(|f| matches!(f.category, Category::Compliance)).count();
        
        println!();
        println!("{}", "Finding Categories".bright_magenta().bold());
        println!("{}", "-".repeat(20));
        println!("🔒 Security:    {}", security_findings.to_string().red());
        println!("💰 Cost Opt:    {}", cost_findings.to_string().yellow());
        println!("📋 Compliance:  {}", compliance_findings.to_string().blue());
        println!();
    }

    fn print_iam_findings_table(&self, findings: &[Finding]) {
        if findings.is_empty() {
            println!("{}", "✅ No IAM security issues found!".bright_green().bold());
            return;
        }

        println!("{}", "IAM Findings".bright_blue().bold());
        println!("{}", "-".repeat(20));

        // Group findings by category for better organization
        let mut security_findings = Vec::new();
        let mut cost_findings = Vec::new();
        let mut other_findings = Vec::new();

        for finding in findings {
            match finding.category {
                Category::Security => security_findings.push(finding),
                Category::CostOptimization => cost_findings.push(finding),
                _ => other_findings.push(finding),
            }
        }

        if !security_findings.is_empty() {
            println!("\n{}", "🔒 Security Issues".red().bold());
            for finding in security_findings {
                self.print_finding_row(finding);
            }
        }

        if !cost_findings.is_empty() {
            println!("\n{}", "💰 Cost Optimization".yellow().bold());
            for finding in cost_findings {
                self.print_finding_row(finding);
            }
        }

        if !other_findings.is_empty() {
            println!("\n{}", "📋 Other Issues".blue().bold());
            for finding in other_findings {
                self.print_finding_row(finding);
            }
        }

        println!();
    }

    fn print_finding_row(&self, finding: &Finding) {
        println!("  {} {} {}",
            self.severity_icon(&finding.severity),
            finding.title.bright_white().bold(),
            format!("({})", finding.resource_id).dimmed()
        );
        println!("    {}", finding.description);
        
        // Extract WAF information if available
        if let Some(waf_pillar) = finding.details.get("waf_pillar") {
            if let Some(waf_question) = finding.details.get("waf_question") {
                println!("    {} WAF: {} - {}", 
                    "🏗️".bright_blue(),
                    waf_pillar.as_str().unwrap_or(""),
                    waf_question.as_str().unwrap_or("")
                );
            }
        }
        println!();
    }

    fn print_iam_recommendations(&self, recommendations: &[Recommendation]) {
        if recommendations.is_empty() {
            return;
        }

        println!("{}", "IAM Recommendations".bright_green().bold());
        println!("{}", "-".repeat(20));

        for (i, rec) in recommendations.iter().enumerate() {
            println!("{}. {} {}", 
                (i + 1).to_string().bright_white().bold(),
                self.iam_category_icon(&rec.category),
                rec.title.bright_white().bold()
            );
            println!("   📝 {}", rec.description);
            println!("   🏗️  Effort: {} | 📈 Impact: {}", 
                self.format_effort(&rec.effort),
                self.format_impact(&rec.impact)
            );
            
            if !rec.steps.is_empty() {
                println!("   📋 Implementation Steps:");
                for (step_i, step) in rec.steps.iter().enumerate() {
                    println!("      {}. {}", step_i + 1, step);
                }
            }
            println!();
        }
    }

    fn iam_category_icon(&self, category: &str) -> &str {
        match category {
            "Security" => "🔒",
            "Access Management" => "👤",
            "Compliance" => "📋",
            "Cost" => "💰",
            "CostOptimization" => "💰",
            "Authentication" => "🔐",
            "Authorization" => "🛡️",
            _ => "📌",
        }}

    
}