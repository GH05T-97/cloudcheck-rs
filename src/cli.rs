use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "cloudcheck", about = "Rust-powered cloud misconfiguration scanner")]
pub struct CliArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    #[arg(long)]
    pub iam: bool,

    #[arg(long)]
    pub s3: bool,

    #[arg(long)]
    pub lambda: bool,

    #[arg(long)]
    pub ai_explain: bool,
}
