mod cli;
mod aws;
mod checks;
mod output;
mod ai;
mod types;

use clap::Parser;
use cli::CliArgs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    let config = aws::load_config(&args.profile, &args.region).await?;

    if args.iam {
        checks::iam::check_iam(&config, args.ai_explain).await?;
    }

    if args.s3 {
        checks::s3::check_s3(&config, args.ai_explain).await?;
    }

    if args.lambda {
        checks::lambda::check_lambda(&config, args.ai_explain).await?;
    }

    Ok(())
}
