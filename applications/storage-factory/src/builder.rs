// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::env;

use crate::error::StorageFactoryError;

/// Storage adapter types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageType {
    /// AWS KMS storage
    #[cfg(feature = "aws-kms")]
    AwsKms,
    /// HashiCorp Vault storage
    #[cfg(feature = "vault")]
    Vault,
    /// File system storage (for development)
    FileSystem,
    /// Third-party service (e.g., DFNS)
    ThirdParty(String),
}

/// Builder for creating storage adapters
/// 
/// Provides explicit, type-safe methods for building specific storage adapters.
/// Each adapter type has its own dedicated `build_*()` method that returns
/// the concrete adapter type, avoiding runtime magic and maintaining clear APIs.
/// 
/// # Usage
/// ```rust,no_run
/// # use storage_factory::StorageBuilder;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // AWS KMS adapter
/// let aws_storage = StorageBuilder::new()
///     .aws_kms()
///     .with_region("us-east-1".to_string())
///     .build_aws_kms()
///     .await?;
/// 
/// // Future: File system adapter  
/// // let fs_storage = StorageBuilder::new()
/// //     .file_system()
/// //     .build_file_system()
/// //     .await?;
/// # Ok(())
/// # }
/// ```
pub struct StorageBuilder {
    storage_type: Option<StorageType>,
    configuration: StorageConfiguration,
}

/// Configuration options for different storage types
#[derive(Debug, Clone, Default)]
pub struct StorageConfiguration {
    /// AWS-specific configuration
    pub aws_region: Option<String>,
    pub aws_kms_key_id: Option<String>,

    /// Vault-specific configuration
    pub vault_addr: Option<String>,
    pub vault_token: Option<String>,
    pub vault_mount_path: Option<String>,

    /// File system configuration
    pub fs_storage_path: Option<String>,

    /// Third-party service configuration
    pub service_api_endpoint: Option<String>,
    pub service_api_key: Option<String>,

    /// General configuration
    pub environment: Environment,
}

/// Environment types
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum Environment {
    #[default]
    Development,
    Testing,
    Production,
}

impl StorageBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            storage_type: None,
            configuration: StorageConfiguration::default(),
        }
    }



    /// Configure for AWS KMS
    #[cfg(feature = "aws-kms")]
    pub fn aws_kms(mut self) -> Self {
        self.storage_type = Some(StorageType::AwsKms);
        self
    }

    /// Configure for HashiCorp Vault
    #[cfg(feature = "vault")]
    pub fn vault(mut self) -> Self {
        self.storage_type = Some(StorageType::Vault);
        self
    }

    /// Configure for file system storage
    pub fn file_system(mut self) -> Self {
        self.storage_type = Some(StorageType::FileSystem);
        self
    }


    /// Configure for third-party service
    pub fn third_party(mut self, service_name: String) -> Self {
        self.storage_type = Some(StorageType::ThirdParty(service_name));
        self
    }

    /// Set AWS region
    pub fn with_region(mut self, region: String) -> Self {
        self.configuration.aws_region = Some(region);
        self
    }

    /// Set AWS KMS key ID
    pub fn with_kms_key_id(mut self, key_id: String) -> Self {
        self.configuration.aws_kms_key_id = Some(key_id);
        self
    }

    /// Set Vault server address
    pub fn with_vault_addr(mut self, addr: String) -> Self {
        self.configuration.vault_addr = Some(addr);
        self
    }

    /// Set Vault authentication token
    pub fn with_vault_token(mut self, token: String) -> Self {
        self.configuration.vault_token = Some(token);
        self
    }

    /// Set Vault mount path
    pub fn with_vault_mount_path(mut self, mount_path: String) -> Self {
        self.configuration.vault_mount_path = Some(mount_path);
        self
    }

    /// Set file system storage path
    pub fn with_storage_path(mut self, path: String) -> Self {
        self.configuration.fs_storage_path = Some(path);
        self
    }

    /// Set environment
    pub fn with_environment(mut self, env: Environment) -> Self {
        self.configuration.environment = env;
        self
    }

    /// Build AWS KMS storage adapter
    #[cfg(feature = "aws-kms")]
    pub async fn build_aws_kms(
        self,
    ) -> Result<aws_kms_adapter::AwsKmsStorage, StorageFactoryError> {
        // Try profile-based authentication first, then fall back to env vars
        let storage = if env::var("AWS_PROFILE").is_ok() {
            let profile_name = env::var("AWS_PROFILE").ok();
            aws_kms_adapter::AwsKmsStorage::with_profile(profile_name.as_deref())
                .await
                .map_err(|e| StorageFactoryError::AdapterInitialization(e.to_string()))?
        } else {
            let mut config = aws_kms_adapter::AwsKmsConfig::from_env()
                .map_err(|e| StorageFactoryError::MissingConfiguration(e.to_string()))?;

            if let Some(region) = self.configuration.aws_region {
                config = config.with_region(region);
            }

            if let Some(key_id) = self.configuration.aws_kms_key_id {
                config = config.with_key_id(key_id);
            }

            aws_kms_adapter::AwsKmsStorage::new(config)
                .await
                .map_err(|e| StorageFactoryError::AdapterInitialization(e.to_string()))?
        };

        Ok(storage)
    }

    /// Build HashiCorp Vault storage adapter
    #[cfg(feature = "vault")]
    pub async fn build_vault(
        self,
    ) -> Result<vault_adapter::VaultStorage, StorageFactoryError> {
        let mut config = vault_adapter::VaultConfig::from_env()
            .map_err(|e| StorageFactoryError::MissingConfiguration(e.to_string()))?;

        // Override with builder configuration if provided
        if let Some(addr) = self.configuration.vault_addr {
            config.addr = addr;
        }

        if let Some(token) = self.configuration.vault_token {
            config.token = token;
        }

        if let Some(mount_path) = self.configuration.vault_mount_path {
            config.mount_path = mount_path;
        }

        let storage = vault_adapter::VaultStorage::new(config)
            .await
            .map_err(|e| StorageFactoryError::AdapterInitialization(e.to_string()))?;

        Ok(storage)
    }

    // Future adapter builders will be added here when implemented:
    // - build_file_storage() 
    // - build_wasm()
    // - build_dfns()

}

impl Default for StorageBuilder {
    fn default() -> Self {
        Self::new()
    }
}
