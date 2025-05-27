use aws_sdk_lambda::Client;
use aws_config::SdkConfig;
use crate::output::print_findings;
use anyhow::Result;

pub async fn check_lambda(config: &SdkConfig, _ai_explain: bool) -> Result<()> {
    let client = Client::new(config);

    println!("🔍 Scanning Lambda environment variables for secrets...");

    let funcs = client.list_functions().send().await?;
    let mut findings = vec![];

    for func in funcs.functions().unwrap_or(&[]) {
        let name = func.function_name().unwrap_or_default();
        let conf = client.get_function_configuration().function_name(name).send().await?;

        if let Some(env) = conf.environment() {
            if let Some(vars) = env.variables() {
                for (key, value) in vars {
                    if key.to_lowercase().contains("secret")
                        || key.to_lowercase().contains("token")
                        || key.to_lowercase().contains("key")
                    {
                        findings.push((name.to_string(), format!("{key}={value}")));
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        println!("✅ No Lambda secrets detected in env vars.");
    } else {
        println!("❗Potential secrets found in Lambda functions:");
        print_findings(&findings);
    }

    Ok(())
}
