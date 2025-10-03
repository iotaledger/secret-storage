// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use secret_storage_core::{
    KeyDelete, KeyExist, KeyGenerate, KeyGet, KeySign, Result, SignatureScheme,
};
use uuid::Uuid;

use crate::{
    VaultConfig, VaultError, VaultSigner,
    utils::vault_client::VaultClient,
    utils::{
        key_utils::validate_key_name,
        vault_operations::{create_signing_key, get_public_key, key_exists, delete_key},
    },
};

/// HashiCorp Vault storage implementation
pub struct VaultStorage {
    client: VaultClient,
}

impl VaultStorage {
    /// Create new Vault storage
    pub async fn new(config: VaultConfig) -> Result<Self> {
        let client = VaultClient::new(config)?;
        Ok(Self { client })
    }

    /// Create Vault storage from environment variables
    pub async fn from_env() -> Result<Self> {
        let config = VaultConfig::from_env()?;
        Self::new(config).await
    }
}

/// Generic signature scheme for HashiCorp Vault
pub struct VaultSignatureScheme;

impl SignatureScheme for VaultSignatureScheme {
    type PublicKey = Vec<u8>;
    type Signature = Vec<u8>;
    type Input = Vec<u8>;
}

/// Options for key generation in Vault
#[derive(Debug, Default)]
pub struct VaultKeyOptions {
    /// Optional key description
    pub description: Option<String>,
    /// Key name (if not provided, a UUID will be generated)
    pub key_name: Option<String>,
}

impl VaultKeyOptions {
    /// Create new VaultKeyOptions with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set key description
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Set key name
    pub fn with_key_name(mut self, key_name: &str) -> Self {
        self.key_name = Some(key_name.to_string());
        self
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGenerate<VaultSignatureScheme, String> for VaultStorage {
    type Options = VaultKeyOptions;

    async fn generate_key_with_options(&self, options: Self::Options) -> Result<(String, Vec<u8>)> {
        // Generate key name if not provided
        let key_name = options
            .key_name
            .unwrap_or_else(|| format!("iota-key-{}", Uuid::new_v4()));

        // Validate key name
        validate_key_name(&key_name)?;

        // Create the signing key in Vault
        create_signing_key(&self.client, &key_name, options.description.as_deref())
            .await
            .map_err(|e| VaultError::General(format!("Failed to create key: {}", e)))?;

        // Get the public key
        let public_key = get_public_key(&self.client, &key_name)
            .await
            .map_err(|e| VaultError::General(format!("Failed to get public key: {}", e)))?;

        Ok((key_name, public_key))
    }
}

impl KeySign<VaultSignatureScheme, String> for VaultStorage {
    fn get_signer(
        &self,
        key_id: &String,
    ) -> Result<impl secret_storage_core::Signer<VaultSignatureScheme, KeyId = String>> {
        // Validate key name
        validate_key_name(key_id)?;

        Ok(VaultSigner::new(
            VaultClient::new(self.client.config().clone())?,
            key_id.clone(),
        ))
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyDelete<String> for VaultStorage {
    async fn delete(&self, key_id: &String) -> Result<()> {
        validate_key_name(key_id)?;
        
        delete_key(&self.client, key_id)
            .await
            .map_err(|e| VaultError::General(format!("Failed to delete key: {}", e)).into())
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyExist<String> for VaultStorage {
    async fn exist(&self, key_id: &String) -> Result<bool> {
        validate_key_name(key_id)?;
        
        key_exists(&self.client, key_id)
            .await
            .map_err(Into::into)
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGet<VaultSignatureScheme, String> for VaultStorage {
    async fn public_key(&self, key_id: &String) -> Result<Vec<u8>> {
        validate_key_name(key_id)?;
        
        get_public_key(&self.client, key_id)
            .await
            .map_err(|e| VaultError::General(format!("Failed to get public key: {}", e)).into())
    }
}