// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::VaultError;

/// Validate that the provided key name is safe for Vault operations
pub fn validate_key_name(key_name: &str) -> Result<(), VaultError> {
    if key_name.is_empty() {
        return Err(VaultError::General("Key name cannot be empty".to_string()));
    }

    // Vault key names should be alphanumeric with dashes and underscores
    if !key_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(VaultError::General(
            "Key name can only contain alphanumeric characters, dashes, and underscores".to_string()
        ));
    }

    if key_name.len() > 100 {
        return Err(VaultError::General("Key name too long (max 100 characters)".to_string()));
    }

    Ok(())
}

/// Hash input data using SHA-256
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}