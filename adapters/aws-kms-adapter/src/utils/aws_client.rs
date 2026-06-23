// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! AWS client configuration utilities

use aws_sdk_kms::Client as KmsClient;

use crate::AwsKmsConfig;
use secret_storage::Result;

#[cfg(feature = "profile")]
use secret_storage::Error;

pub async fn create_kms_client_from_config(config: &AwsKmsConfig) -> Result<KmsClient> {
  let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
    .region(aws_config::Region::new(config.region.clone()))
    .load()
    .await;

  Ok(KmsClient::new(&aws_config))
}

#[cfg(feature = "profile")]
/// Create KMS client with AWS profile support
pub(crate) async fn create_kms_client_with_profile(profile_name: Option<&str>) -> Result<(KmsClient, AwsKmsConfig)> {
  let mut builder = aws_config::defaults(aws_config::BehaviorVersion::latest());

  if let Some(profile) = profile_name {
    builder = builder.profile_name(profile);
  }

  let aws_config = builder.load().await;
  let client = KmsClient::new(&aws_config);

  // Get region from AWS config or return an error
  let region = aws_config
    .region()
    .map(|r| r.as_ref().to_string())
    .ok_or_else(|| Error::InvalidConfig("Region not defined in profile".to_string()))?;

  let config = AwsKmsConfig::new(region);

  Ok((client, config))
}
