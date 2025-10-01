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

}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<VaultSignatureScheme> for VaultSigner {
    type KeyId = String;

    fn key_id(&self) -> Self::KeyId {
        self.key_name.clone()
    }

    async fn sign(&self, input: &Vec<u8>) -> Result<Vec<u8>> {
        // ECDSA P-256 (secp256r1): sign pre-hashed data (Blake2b-256 digest, 32 bytes)
        println!("🔍 ECDSA P-256 (secp256r1): signing pre-hashed data ({} bytes)", input.len());
        let signature = sign_data(&self.client, &self.key_name, input)
            .await
            .map_err(|e| VaultError::General(format!("Failed to sign data with ECDSA: {}", e)))?;
        Ok(signature)
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        get_public_key(&self.client, &self.key_name)
            .await
            .map_err(|e| VaultError::General(format!("Failed to get public key: {}", e)).into())
    }
}