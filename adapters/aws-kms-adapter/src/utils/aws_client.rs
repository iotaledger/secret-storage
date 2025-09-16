// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! AWS client configuration utilities

use aws_sdk_kms::Client as KmsClient;
use std::env;

use crate::AwsKmsConfig;
use secret_storage_core::Result;

/// Create KMS client from config
pub async fn create_kms_client_from_config(config: &AwsKmsConfig) -> Result<KmsClient> {
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;
    Ok(KmsClient::new(&aws_config))
}

/// Create KMS client with AWS profile support
pub async fn create_kms_client_with_profile(profile_name: Option<&str>) -> Result<(KmsClient, AwsKmsConfig)> {
    let mut builder = aws_config::defaults(aws_config::BehaviorVersion::latest());

    if let Some(profile) = profile_name {
        builder = builder.profile_name(profile);
    }

    let aws_config = builder.load().await;
    let client = KmsClient::new(&aws_config);

    // Get region from AWS config or environment
    let region = aws_config
        .region()
        .map(|r| r.as_ref().to_string())
        .or_else(|| env::var("AWS_REGION").ok())
        .or_else(|| env::var("AWS_DEFAULT_REGION").ok())
        .unwrap_or_else(|| "eu-west-1".to_string()); // Default region

    let config = AwsKmsConfig::new(region);

    Ok((client, config))
}

