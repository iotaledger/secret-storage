// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::env;
use crate::VaultError;

/// Configuration for HashiCorp Vault adapter
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Vault server address
    pub addr: String,
    /// Vault authentication token
    pub token: String,
    /// Transit secrets engine mount path
    pub mount_path: String,
}

impl VaultConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Result<Self, VaultError> {
        let addr = env::var("VAULT_ADDR")
            .map_err(|_| VaultError::Configuration("VAULT_ADDR environment variable not set".to_string()))?;
        
        let token = env::var("VAULT_TOKEN")
            .map_err(|_| VaultError::Configuration("VAULT_TOKEN environment variable not set".to_string()))?;
        
        let mount_path = env::var("VAULT_MOUNT_PATH")
            .unwrap_or_else(|_| "transit".to_string());

        Ok(Self {
            addr,
            token,
            mount_path,
        })
    }

    /// Create new configuration
    pub fn new(addr: String, token: String, mount_path: Option<String>) -> Self {
        Self {
            addr,
            token,
            mount_path: mount_path.unwrap_or_else(|| "transit".to_string()),
        }
    }
}