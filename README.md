# 🔍 AI-Powered Multi-Cloud Infrastructure Analyzer (MVP)

A high-performance, Rust-based CLI tool that scans cloud environments and uses AI to deliver actionable insights on **security**, **cost**, **performance**, and **resilience**.

---

## ✨ Features (MVP)

Currently supports **AWS** infrastructure scanning:

- ✅ Scan **S3 buckets** for public access or insecure permissions
- ✅ Audit **IAM roles/users/policies** for risky configurations
- ✅ Inspect **Lambda functions** for potential security issues
- ✅ **AI-powered explanations and suggestions** using OpenAI GPT

---

## 🚀 Roadmap

Future versions will include:

- 🌐 **Multi-cloud support** (GCP, Azure, DigitalOcean, Hetzner, Akamai Cloud, IBM Cloud)
- 🤖 **AI-driven recommendations**:
  - Disaster recovery planning
  - Security posture improvements
  - Performance tuning
  - Cost optimizations using telemetry/metrics
- 📄 Scanning **Infrastructure-as-Code** and **CI/CD pipelines**
- 🧠 Use of **ML, RAG, and LLM fine-tuning** for deeper contextual analysis

---

## 🛠️ Tech Stack

- 🦀 **Rust** – high-performance, memory-safe system programming
- ☁️ **AWS SDK for Rust** – interface with AWS services
- 🤖 **OpenAI API** – LLMs for intelligent suggestions
- ⚡ **Tokio** – asynchronous runtime for concurrency
- 🔐 Designed with a focus on **security-first** practices

---

## ⚡ Why This Matters

Cloud complexity continues to grow. This tool helps:

- Engineers gain fast visibility into misconfigurations
- Teams automate security audits and cost reviews
- Organizations improve cloud posture with minimal overhead

---

## 📌 Status

This is an early MVP and portfolio project. It's under active development and open to feedback, collaboration, and contributions.

---


## 📫 Dev-First Traction Strategy - MVP
🔧 **Core CLI Capabilities**
✅ Multi-service scanning (AWS only to start)

aws s3 — Detect public buckets (ACLs + policies)

aws iam — Detect overly permissive roles/policies

aws lambda — Flag functions with wide privileges, missing timeouts, excessive runtime

Bonus: aws ec2 — Public IPs, unencrypted volumes

✅ **AI-powered explanations**

Flag: “S3 bucket is public”

Explain: “This bucket allows AllUsers access. Anyone on the internet can read or write to it.”

Suggest: “Apply a bucket policy denying all non-org traffic or use block public access settings.”

✅ **JSON output mode**

--json for CI pipelines or further analysis

✅ **Config-based execution**

.cloudscanner.toml or YAML support (define account, regions, what to scan)

🔐 **Security & Trust**
No data sent to your servers by default

Clear audit logs: what was scanned, where, and what happened

Safe-mode / dry-run options

Support AWS_PROFILE, env vars, or creds securely loaded from ~/.aws

🧠 **LLM Integration**
--explain-with-ai to get GPT-style explanations + suggestions per finding

Ask: "What’s the risk of this IAM policy?"

Early OpenAI key input via env var or config

⚙️ **CI/CD Ready**
GitHub Action: uses: your-org/cloudscanner-action@v1

Detect secrets, public resources, and dangerous defaults before merging

📄 **Output & Reporting**
Markdown report output: --report md

CI-friendly summary at the end

**Slack/Webhook notification**

✨ Bonus “Nice-to-Haves” (That Devs Love)
scan --local — scan Terraform / CDK / CloudFormation for risks statically

scan --diff — highlight what changed since last scan

scan --score — assign a security score (gamify it)

scan --fix — suggest CLI-level autofixes where possible

Plugins/extensions: “Add your own rule with a simple Rust script or JSON file”

**Dashboard**
1. **Historical Scan Log** - View previous scans with timestamps, Simple table: Scan ID, account, date, number of findings, score, Click to view detailed report

2. **Misconfiguration Findings** - Viewer Group by resource type (S3, IAM, Lambda, etc.), Severity indicators: Low / Medium / High, Explanation + Recommendation (AI generated, or CLI-powered)

3. **Security Score + Trend** - 0–100 score per scan, Visual indicator if it’s improving or getting worse, Scoring algorithm can be basic (e.g., #critical findings per 100 resources)

4. **Simple Project/Environment View** - Let users tag scans as prod, staging, or dev, Filter findings by environment, Keep dashboards tidy across accounts or clients

5. **Quick Onboarding & Auth** - GitHub or Google OAuth, Magic link login, No need to create a password

6. **Secure CLI-to-Dashboard Upload**
Dev runs:

cloudscanner scan --dashboard
Result is uploaded via short-lived token or signed link

Redirects to view scan in browser

7. **Light Theming & UX Polishing** - Dark mode, Fast-loading UI, No clutter — focused layout

8. **Feedback or “Suggest a Feature"** - Button for devs to suggest scanning rules or improvements




