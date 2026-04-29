// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_sdk_kms::Client as KmsClient;
use secret_storage::Result;

use crate::create_kms_client_from_config;
use crate::AwsKmsConfig;
use crate::AwsKmsError;
use crate::AwsKmsSigner;
use crate::KeySpec as AdapterKeySpec;

const KEY_DELETION_PENDING_WINDOW_IN_DAYS: i32 = 7;

/// generic default values in adapter creation
/// Options for key generation in AWS KMS
#[derive(Clone, Debug, Default)]
pub struct AwsKmsKeyOptions {
  /// Optional key policy
  pub policy: Option<String>,
  /// Optional key description
  pub description: Option<String>,
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

impl AwsKmsStorage {
  /// Create new AWS KMS storage
  pub async fn from_config(config: AwsKmsConfig) -> Result<Self> {
    let client = create_kms_client_from_config(&config).await?;
    Ok(Self { client, config })
  }

  // assign key options to allow env/profile initialization with custom key properties
  pub fn with_key_options(self, key_options: AwsKmsKeyOptions) -> Self {
    Self {
      config: self.config.with_key_options(key_options),
      ..self
    }
  }

  pub async fn from_client(client: KmsClient, config: AwsKmsConfig) -> Result<Self> {
    Ok(Self { client, config })
  }
}

#[cfg(feature = "profile")]
mod from_profile {
  use crate::create_kms_client_with_profile;

  use super::*;

  impl AwsKmsStorage {
    /// Create AWS KMS storage with profile support
    pub async fn from_profile(profile_name: Option<&str>) -> Result<Self> {
      let (client, config) = create_kms_client_with_profile(profile_name).await?;
      Ok(Self { client, config })
    }
  }
}

#[cfg(feature = "env")]
mod from_env {
  use super::*;

  impl AwsKmsStorage {
    /// Create AWS KMS storage from environment variables
    pub async fn from_env() -> Result<Self> {
      let config = AwsKmsConfig::from_env()?;
      Self::from_config(config).await
    }
  }
}

// helper functions for building signature trait implementations
impl AwsKmsStorage {
  pub(crate) async fn generate_key(&self, key_spec: AdapterKeySpec) -> Result<(String, Vec<u8>)> {
    let mut create_key = self
      .client
      .create_key()
      .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
      .key_spec(key_spec.try_into()?);

    if let Some(description) = &self.config.key_options.description {
      create_key = create_key.description(description);
    } else {
      create_key = create_key.description(format!("IOTA Secret Storage Key ({key_spec})"));
    }

    if let Some(policy) = &self.config.key_options.policy {
      create_key = create_key.policy(policy);
    }

    // Add tags if provided
    if !self.config.key_options.tags.is_empty() {
      let tags = self
        .config
        .key_options
        .tags
        .iter()
        .map(|(k, v)| {
          aws_sdk_kms::types::Tag::builder()
            .tag_key(k)
            .tag_value(v)
            .build()
            .map_err(|err| AwsKmsError::Configuration(format!("Failed to construct tags from config; {err}.")))
        })
        .collect::<Result<Vec<_>, _>>()?;
      create_key = create_key.set_tags(Some(tags));
    }

    // Execute KMS key creation
    let create_response = create_key.send().await.map_err(|e| {
      AwsKmsError::General(format!(
        "Failed to create KMS key: {}",
        e.as_service_error()
          .map(|se| format!(": {}", &se.meta()))
          .unwrap_or_default()
      ))
    })?;

    let kms_key_id = create_response
      .key_metadata
      .map(|metadata| metadata.key_id)
      .ok_or_else(|| AwsKmsError::General("No key ID returned from KMS".to_string()))?;

    // Get the public key immediately after creation
    let public_key_response = self
      .client
      .get_public_key()
      .key_id(&kms_key_id)
      .send()
      .await
      .map_err(|e| AwsKmsError::General(format!("Failed to get public key: {}", e)))?;

    let public_key_der = public_key_response
      .public_key
      .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
      .into_inner();

    Ok((kms_key_id, public_key_der))
  }

  pub(crate) async fn delete_key(&self, key_id: &str, pending_window_in_days: Option<i32>) -> Result<()> {
    self
      .client
      .schedule_key_deletion()
      .key_id(key_id)
      .pending_window_in_days(pending_window_in_days.unwrap_or(KEY_DELETION_PENDING_WINDOW_IN_DAYS))
      .send()
      .await
      .map_err(|e| AwsKmsError::General(format!("Failed to schedule key deletion: {}", e)))?;

    Ok(())
  }

  pub(crate) fn get_signer_with_key_spec(&self, key_id: &String, key_spec: AdapterKeySpec) -> Result<AwsKmsSigner> {
    Ok(AwsKmsSigner::new(self.client.clone(), key_id.clone(), key_spec))
  }
}
