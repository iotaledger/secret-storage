// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use secret_storage_core::{Result, Signer};
use crate::{
    VaultSignatureScheme, VaultError,
    utils::{vault_operations::{sign_data, get_public_key}, vault_client::VaultClient},
};

/// Vault signer implementation
pub struct VaultSigner {
    client: VaultClient,
    key_name: String,
}

impl VaultSigner {
    /// Create new Vault signer
    pub fn new(client: VaultClient, key_name: String) -> Self {
        Self { client, key_name }
    }

    /// Get the key name for this signer
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Check if this key is Ed25519 by examining the key metadata
    async fn is_ed25519_key(&self) -> Result<bool> {
        let path = format!("{}/keys/{}", self.client.config().mount_path, self.key_name);
        
        match self.client.get(&path).await {
            Ok(response) => {
                // Check the key type from the response
                if let Some(key_type) = response.get("data")
                    .and_then(|d| d.get("type"))
                    .and_then(|t| t.as_str()) {
                    Ok(key_type == "ed25519")
                } else {
                    // If we can't determine the type, assume ECDSA for backward compatibility
                    Ok(false)
                }
            }
            Err(_) => {
                // If we can't get key info, assume ECDSA for backward compatibility
                Ok(false)
            }
        }
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<VaultSignatureScheme> for VaultSigner {
    type KeyId = String;

    fn key_id(&self) -> Self::KeyId {
        self.key_name.clone()
    }

    async fn sign(&self, input: &Vec<u8>) -> Result<Vec<u8>> {
        // Determine if we're dealing with raw data or pre-hashed data
        // For Ed25519: we need to sign raw transaction data (IOTA serialized data, usually 200+ bytes)
        // For ECDSA: we can sign pre-hashed data (Blake2b-256 digest, 32 bytes)
        
        // First, check what type of key we have by attempting to get its info
        let is_ed25519 = self.is_ed25519_key().await?;
        
        if is_ed25519 {
            // Ed25519 case: sign raw data directly
            // Ed25519 in Vault does its own hashing internally
            println!("🔍 Ed25519 detected: signing raw data ({} bytes)", input.len());
            let signature = sign_data(&self.client, &self.key_name, input)
                .await
                .map_err(|e| VaultError::General(format!("Failed to sign data with Ed25519: {}", e)))?;
            Ok(signature)
        } else {
            // ECDSA case: sign pre-hashed data
            println!("🔍 ECDSA detected: signing pre-hashed data ({} bytes)", input.len());
            let signature = sign_data(&self.client, &self.key_name, input)
                .await
                .map_err(|e| VaultError::General(format!("Failed to sign data with ECDSA: {}", e)))?;
            Ok(signature)
        }
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        get_public_key(&self.client, &self.key_name)
            .await
            .map_err(|e| VaultError::General(format!("Failed to get public key: {}", e)).into())
    }
}