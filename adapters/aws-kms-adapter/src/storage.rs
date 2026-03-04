// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_sdk_kms::Client as KmsClient;
use secret_storage::Result;
use uuid::Uuid;

use crate::create_kms_client_from_config;
use crate::AwsKmsConfig;
use crate::AwsKmsError;
use crate::AwsKmsSigner;
use crate::KeySpec as AdapterKeySpec;

/// generic default values in adapter creation
/// Options for key generation in AWS KMS
#[derive(Clone, Debug, Default)]
pub struct AwsKmsKeyOptions {
  /// Optional key policy
  pub policy: Option<String>,
  /// Optional key description
  pub description: Option<String>,
  /// Alias
  pub alias: Option<String>,
  /// Optional tags
  pub tags: Vec<(String, String)>,
  /// Optional KeySpec to use
  pub key_spec: Option<AdapterKeySpec>,
}

/// AWS KMS storage implementation
pub struct AwsKmsStorage {
  pub client: KmsClient,
  #[allow(dead_code)]
  pub(crate) config: AwsKmsConfig,
}

/// public behavior
impl AwsKmsStorage {
  /// Create new AWS KMS storage
  pub async fn new(config: AwsKmsConfig) -> Result<Self> {
    let client = create_kms_client_from_config(&config).await?;
    Ok(Self { client, config })
  }
}
// helper functions for building signature trait implementations
impl AwsKmsStorage {
  // pub(crate) async fn generate_key(&self, options: AwsKmsKeyOptions) -> Result<(String, Vec<u8>)> {
  pub(crate) async fn generate_key(&self, key_spec: AdapterKeySpec) -> Result<(String, Vec<u8>)> {
    // If no alias is provided, generate a unique one
    let key_alias = self
      .config
      .key_options
      .alias
      .clone()
      .unwrap_or_else(|| format!("{}", Uuid::new_v4()));

    self.client.create_alias().set_alias_name(Some(key_alias.clone()));

    let mut create_key = self
      .client
      .create_key()
      .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
      .key_spec(key_spec.try_into().unwrap());

    if let Some(description) = &self.config.key_options.description {
      create_key = create_key.description(description);
    } else {
      create_key = create_key.description(format!("IOTA Secret Storage Key ({key_spec}) - {key_alias}",));
    }

    if let Some(policy) = &self.config.key_options.policy {
      create_key = create_key.policy(policy);
    }

    // Add tags if provided
    if !self.config.key_options.tags.is_empty() {
      let tags: Vec<_> = self
        .config
        .key_options
        .tags
        .iter()
        .map(|(k, v)| {
          aws_sdk_kms::types::Tag::builder()
            .tag_key(k)
            .tag_value(v)
            .build()
            .unwrap()
        })
        .collect();
      create_key = create_key.set_tags(Some(tags));
    }

    // Execute KMS key creation
    let create_response = create_key
      .send()
      .await
      .map_err(|e| AwsKmsError::General(format!("Failed to create KMS key: {}", e)))?;

    let kms_key_id = create_response
      .key_metadata
      .map(|metadata| metadata.key_id)
      .ok_or_else(|| AwsKmsError::General("No key ID returned from KMS".to_string()))?;

    // Create the alias for the key (AWS requires 'alias/' prefix)
    let aws_alias_name = format!("alias/{}", key_alias);

    self
      .client
      .create_alias()
      .alias_name(&aws_alias_name)
      .target_key_id(&kms_key_id)
      .send()
      .await
      .map_err(|e| AwsKmsError::General(format!("Failed to create alias: {}", e)))?;

    // Get the public key immediately after creation using the alias
    let public_key_response = self
      .client
      .get_public_key()
      .key_id(&aws_alias_name)
      .send()
      .await
      .map_err(|e| AwsKmsError::General(format!("Failed to get public key: {}", e)))?;

    let public_key_der = public_key_response
      .public_key
      .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
      .into_inner();

    // Return the original alias as the key identifier (without 'alias/' prefix for user display)
    // Ok((key_alias, public_key_der))
    Ok((kms_key_id, public_key_der))
  }

  // to be removed
  // shared behavior between signer and storage, so keeping it in helper function
  // pub(crate) async fn get_public_key_der(&self, key_id: &str) -> Result<(Vec<u8>, KeySpec)> {
  //     // AWS KMS get_public_key accepts both aliases and KMS key IDs
  //     let public_key_response = self
  //         .client
  //         .get_public_key()
  //         .key_id(key_id)
  //         .send()
  //         .await
  //         .map_err(|e| {
  //             AwsKmsError::General(format!(
  //                 "Failed to get public key from KMS: {}",
  //                 e.into_source().unwrap()
  //             ))
  //         })
  //         .unwrap();

  //     // Get the actual KMS key ID for logging and validation
  //     let actual_key_id = public_key_response.key_id.as_deref().unwrap_or("unknown");

  //     // Verify it's the expected key type
  //     if let Some(key_usage) = public_key_response.key_usage {
  //         if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
  //             return Err(AwsKmsError::General(format!(
  //                 "Key {} (actual ID: {}) is not for signing, got usage: {:?}",
  //                 key_id, actual_key_id, key_usage
  //             ))
  //             .into());
  //         }
  //     }

  //     let key_spec = public_key_response.key_spec().ok_or_else(|| {
  //         Err(
  //             AwsKmsError::General(format!("Key {} is missing KeySpec information", key_id))
  //                 .into(),
  //         )
  //     })?;

  //     let public_key_der = public_key_response
  //         .public_key
  //         .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
  //         .into_inner();

  //     Ok((public_key_der, key_spec.clone()))
  // }

  //   async fn delete(&self, key_id: &str, pending_window_in_days: Option<i32>) -> Result<()> {
  //     self
  //       .client
  //       .schedule_key_deletion()
  //       .key_id(key_id)
  //       .pending_window_in_days(pending_window_in_days.unwrap_or(DEFAULT_PENDING_WINDOW_IN_DAYS))
  //       .send()
  //       .await
  //       .unwrap();
  //     Ok(())
  //   }

  pub(crate) fn get_signer_with_key_spec(&self, key_id: &String, key_spec: AdapterKeySpec) -> Result<AwsKmsSigner> {
    Ok(AwsKmsSigner::new(self.client.clone(), key_id.clone(), key_spec))
  }
}
