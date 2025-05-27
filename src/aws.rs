use aws_config::meta::region::RegionProviderChain;
use aws_config::SdkConfig;
use aws_types::region::Region;
use anyhow::Result;

/// Load AWS SDK config using profile and region name
pub async fn load_config(profile: &str, region: &str) -> Result<SdkConfig> {
    let region_provider = RegionProviderChain::first_try(Some(Region::new(region.to_string())))
        .or_default_provider()
        .or_else(Region::new("us-east-1"));

    let config = aws_config::from_env()
        .region(region_provider)
        .profile_name(profile)
        .load()
        .await;

    Ok(config)
}
