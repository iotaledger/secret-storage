// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::env;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// API server configuration
    pub api_host: String,
    pub api_port: u16,

    /// Storage backend type
    pub storage_backend: StorageBackend,

    /// Vault configuration (if using Vault backend)
    pub vault: Option<VaultConfig>,

    /// AWS configuration (if using AWS backend)
    pub aws: Option<AwsConfig>,

    /// IOTA network configuration
    pub iota_network: String,

    /// Environment type
    pub environment: String,
}

/// Storage backend type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    Vault,
    Aws,
}

/// Vault specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub addr: String,
    pub token: String,
    pub mount_path: String,
}

/// AWS specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    pub profile: Option<String>,
    pub key_id: Option<String>,
}

impl AppConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        // Load .env file if present (but don't override existing env vars)
        // dotenvy::dotenv().ok();  // Disabled to allow env vars to take precedence

        let api_host = env::var("API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let api_port = env::var("API_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .map_err(|e| format!("Invalid API_PORT: {}", e))?;

        let storage_backend = match env::var("STORAGE_BACKEND")
            .unwrap_or_else(|_| "vault".to_string())
            .to_lowercase()
            .as_str()
        {
            "vault" => StorageBackend::Vault,
            "aws" => StorageBackend::Aws,
            backend => {
                return Err(format!("Unsupported storage backend: {}", backend).into())
            }
        };

        let vault = if matches!(storage_backend, StorageBackend::Vault) {
            Some(VaultConfig {
                addr: env::var("VAULT_ADDR")
                    .map_err(|_| "VAULT_ADDR not set")?,
                token: env::var("VAULT_TOKEN")
                    .map_err(|_| "VAULT_TOKEN not set")?,
                mount_path: env::var("VAULT_MOUNT_PATH")
                    .unwrap_or_else(|_| "transit".to_string()),
            })
        } else {
            None
        };

        let aws = if matches!(storage_backend, StorageBackend::Aws) {
            Some(AwsConfig {
                region: env::var("AWS_REGION")
                    .map_err(|_| "AWS_REGION not set")?,
                profile: env::var("AWS_PROFILE").ok(),
                key_id: env::var("KMS_KEY_ID").ok(),
            })
        } else {
            None
        };

        let iota_network = env::var("IOTA_NETWORK").unwrap_or_else(|_| "testnet".to_string());
        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        Ok(Self {
            api_host,
            api_port,
            storage_backend,
            vault,
            aws,
            iota_network,
            environment,
        })
    }
}