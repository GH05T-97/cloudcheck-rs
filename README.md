# 🔍 AI-Powered Multi-Cloud Infrastructure Analyzer

A high-performance, **Rust-based CLI tool** that intelligently scans cloud environments and leverages **Artificial Intelligence** to deliver actionable insights on **security**, **cost optimization**, **performance**, and **resilience**.

---

## ✨ Features (Current MVP)

Currently supports **AWS** infrastructure scanning and provides **AI-driven analysis**:

* ✅ Scans **S3 buckets** for insecure configurations like public access, unencrypted data, or lack of versioning.
* ✅ Audits **IAM roles and policies** to identify overly permissive access or adherence to least privilege.
* ✅ Inspects **Lambda functions** for potential security misconfigurations, such as broad execution privileges or missing timeout settings.
* ✅ Provides **AI-powered explanations and remediation suggestions** for identified findings, leveraging large language models to offer contextual insights and actionable steps.
* ✅ Supports **JSON output** for easy integration into CI/CD pipelines or further analysis.
* ✅ Securely loads **AWS credentials** from environment variables or `~/.aws` configuration, adhering to AWS best practices.


## 🛠️ Tech Stack

* 🦀 **Rust**: High-performance, memory-safe systems programming for reliable and efficient execution.
* ☁️ **AWS SDK for Rust**: Official SDK for seamless and secure interaction with AWS services.
* 🤖 **LLM Integration (OpenAI / Gemini)**: Utilizes large language models for intelligent analysis and actionable recommendations. Designed to be **provider-agnostic** for future flexibility.
* ⚡ **Tokio**: Asynchronous runtime enabling concurrent operations for fast scanning.
* ⚙️ **Configuration Management**: Employs the `config` crate for flexible loading of settings from `config.yaml` files and environment variables, ensuring secure credential handling.
* 🔐 **Security-First Design**: Built with a focus on not sending sensitive data to external servers by default and providing clear audit logging.

---

## ⚡ Why This Matters

As cloud environments grow in complexity, managing their security, cost, performance, and reliability becomes increasingly challenging. This tool aims to empower:

* **Engineers** with fast, actionable visibility into potential misconfigurations.
* **Teams** to automate cloud security audits and cost reviews efficiently.
* **Organizations** to proactively improve their overall cloud posture with minimal manual overhead, reducing risk and optimizing spend.

---

## 📌 Status

This is an early MVP and portfolio project. It's under active development and open to feedback, collaboration, and contributions.

---