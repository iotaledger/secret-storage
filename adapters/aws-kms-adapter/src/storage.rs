// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use aws_sdk_kms::Client as KmsClient;
use secret_storage_core::{
    KeyDelete, KeyExist, KeyGenerate, KeyGet, KeySign, Result, SignatureScheme,
};
use uuid::Uuid;

use crate::{
    AwsKmsConfig, AwsKmsError, AwsKmsSigner,
    utils::{
        aws_client::{create_kms_client_from_config, create_kms_client_with_profile},
        key_utils::identify_key_type,
        kms_operations::{resolve_alias_to_key_id, check_key_exists_and_enabled, delete_alias_if_exists, schedule_key_deletion},
    },
};

/// AWS KMS storage implementation
pub struct AwsKmsStorage {
    client: KmsClient,
    #[allow(dead_code)]
    config: AwsKmsConfig,
}

impl AwsKmsStorage {

    /// Create new AWS KMS storage
    pub async fn new(config: AwsKmsConfig) -> Result<Self> {
        let client = create_kms_client_from_config(&config).await?;
        Ok(Self { client, config })
    }

    /// Create AWS KMS storage from environment variables
    pub async fn from_env() -> Result<Self> {
        let config = AwsKmsConfig::from_env()?;
        Self::new(config).await
    }

    /// Create AWS KMS storage with profile support
    pub async fn with_profile(profile_name: Option<&str>) -> Result<Self> {
        let (client, config) = create_kms_client_with_profile(profile_name).await?;
        Ok(Self { client, config })
    }

}

/// Generic signature scheme for AWS KMS
pub struct AwsKmsSignatureScheme;

impl SignatureScheme for AwsKmsSignatureScheme {
    type PublicKey = Vec<u8>;
    type Signature = Vec<u8>;
    type Input = Vec<u8>;
}

/// Options for key generation in AWS KMS
#[derive(Debug, Default)]
pub struct AwsKmsKeyOptions {
    /// Optional key policy
    pub policy: Option<String>,
    /// Optional key description
    pub description: Option<String>,
    /// Alias
    pub alias: Option<String>,
    /// Optional tags
    pub tags: Vec<(String, String)>,
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGenerate<AwsKmsSignatureScheme, String> for AwsKmsStorage {
    type Options = AwsKmsKeyOptions;

    async fn generate_key_with_options(&self, options: Self::Options) -> Result<(String, Vec<u8>)> {
        // If no alias is provided, generate a unique one
        let key_alias = options
            .alias
            .unwrap_or_else(|| format!("{}", Uuid::new_v4()));

        self.client
            .create_alias()
            .set_alias_name(Some(key_alias.clone()));

        // Create KMS key for signing with secp256r1 (ECC_NIST_P256)
        let mut create_key = self
            .client
            .create_key()
            .key_usage(aws_sdk_kms::types::KeyUsageType::SignVerify)
            .key_spec(aws_sdk_kms::types::KeySpec::EccNistP256);

        if let Some(description) = &options.description {
            create_key = create_key.description(description);
        } else {
            create_key = create_key.description(format!(
                "IOTA Secret Storage Key (secp256r1) - {}",
                key_alias
            ));
        }

        if let Some(policy) = &options.policy {
            create_key = create_key.policy(policy);
        }

        // Add tags if provided
        if !options.tags.is_empty() {
            let tags: Vec<_> = options
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

        // Create the alias for the key
        let normalized_alias = if key_alias.starts_with("alias/") {
            key_alias.clone()
        } else {
            format!("alias/{}", key_alias)
        };

        self.client
            .create_alias()
            .alias_name(&normalized_alias)
            .target_key_id(&kms_key_id)
            .send()
            .await
            .map_err(|e| AwsKmsError::General(format!("Failed to create alias: {}", e)))?;

        // Get the public key immediately after creation using the alias
        let public_key_response = self
            .client
            .get_public_key()
            .key_id(&normalized_alias)
            .send()
            .await
            .map_err(|e| AwsKmsError::General(format!("Failed to get public key: {}", e)))?;

        let public_key_der = public_key_response
            .public_key
            .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
            .into_inner();

        // Return the alias as the key identifier (no internal mapping needed)
        Ok((normalized_alias, public_key_der))
    }
}

impl KeySign<AwsKmsSignatureScheme, String> for AwsKmsStorage {
    fn get_signer(
        &self,
        key_id: &String,
    ) -> Result<impl secret_storage_core::Signer<AwsKmsSignatureScheme, KeyId = String>> {
        let _key_type = identify_key_type(key_id);

        // The signer will determine if this is an alias or KMS key ID internally
        Ok(AwsKmsSigner::new(
            self.client.clone(),
            key_id.clone(),
            key_id.clone(), // Pass the same identifier - signer will handle the distinction
        ))
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyDelete<String> for AwsKmsStorage {
    async fn delete(&self, key_id: &String) -> Result<()> {
        let is_alias = key_id.starts_with("alias/");

        // Get the actual KMS key ID for deletion
        let actual_key_id = if is_alias {
            resolve_alias_to_key_id(&self.client, key_id).await?
        } else {
            key_id.clone()
        };

        // Step 1: If we started with an alias, delete the alias first
        if is_alias {
            delete_alias_if_exists(&self.client, key_id).await?;
        }

        // Step 2: Schedule the KMS key for deletion
        schedule_key_deletion(&self.client, &actual_key_id, None).await?;

        Ok(())
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyExist<String> for AwsKmsStorage {
    async fn exist(&self, key_id: &String) -> Result<bool> {
        check_key_exists_and_enabled(&self.client, key_id).await.map_err(Into::into)
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGet<AwsKmsSignatureScheme, String> for AwsKmsStorage {
    async fn public_key(&self, key_id: &String) -> Result<Vec<u8>> {
        // AWS KMS get_public_key accepts both aliases and KMS key IDs
        let public_key_response = self
            .client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| {
                AwsKmsError::General(format!("Failed to get public key from KMS: {}", e))
            })?;

        let public_key_der = public_key_response
            .public_key
            .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
            .into_inner();

        // Get the actual KMS key ID for logging and validation
        let actual_key_id = public_key_response.key_id.as_deref().unwrap_or("unknown");

        // Verify it's the expected key type
        if let Some(key_usage) = public_key_response.key_usage {
            if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
                return Err(AwsKmsError::General(format!(
                    "Key {} (actual ID: {}) is not for signing, got usage: {:?}",
                    key_id, actual_key_id, key_usage
                ))
                .into());
            }
        }

        if let Some(key_spec) = public_key_response.key_spec {
            if key_spec != aws_sdk_kms::types::KeySpec::EccNistP256 {
                return Err(AwsKmsError::General(format!(
                    "Key {} (actual ID: {}) is not secp256r1, got spec: {:?}",
                    key_id, actual_key_id, key_spec
                ))
                .into());
            }
        }

        Ok(public_key_der)
    }
}
