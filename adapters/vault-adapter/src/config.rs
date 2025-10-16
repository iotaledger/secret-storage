// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::env;
use crate::VaultError;

/// Configuration for HashiCorp Vault adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Vault server address
    pub addr: String,
    /// Vault authentication token (optional when using Vault Agent)
    pub token: Option<String>,
    /// Transit secrets engine mount path
    pub mount_path: String,
    /// Key type specification
    pub key_type: KeyType,
    /// Whether to use Vault Agent sidecar mode (token injected by proxy)
    pub agent_mode: bool,
}

/// Vault Key Type specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    /// ECDSA P-256 for ECDSA signatures
    EcdsaP256,
    /// RSA-2048 for RSA signatures
    Rsa2048,
    /// RSA-4096 for RSA signatures
    Rsa4096,
    /// Ed25519 for EdDSA signatures
    Ed25519,
}

impl VaultConfig {
    /// Create configuration from environment variables
    /// 
    /// # Vault Agent Sidecar Mode
    /// 
    /// Set `VAULT_AGENT_MODE=true` to use Vault Agent sidecar pattern in Kubernetes:
    /// - The app connects to a local Vault Agent proxy (e.g., `http://127.0.0.1:8100`)
    /// - The agent automatically injects `X-Vault-Token` header in all requests
    /// - No `VAULT_TOKEN` environment variable is required
    /// - Token rotation and renewal is handled automatically by the agent
    /// 
    /// Example:
    /// ```bash
    /// export VAULT_ADDR="http://127.0.0.1:8100"
    /// export VAULT_AGENT_MODE="true"
    /// # VAULT_TOKEN not needed - injected by agent
    /// ```
    pub fn from_env() -> Result<Self, VaultError> {
        let addr = env::var("VAULT_ADDR")
            .map_err(|_| VaultError::Configuration("VAULT_ADDR environment variable not set".to_string()))?;

        // Check if using Vault Agent sidecar mode
        let agent_mode = env::var("VAULT_AGENT_MODE")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        // Token is optional when using Vault Agent
        let token = if agent_mode {
            None
        } else {
            Some(env::var("VAULT_TOKEN")
                .map_err(|_| VaultError::Configuration(
                    "VAULT_TOKEN environment variable not set. Use VAULT_AGENT_MODE=true if using Vault Agent sidecar".to_string()
                ))?)
        };

        let mount_path = env::var("VAULT_MOUNT_PATH")
            .unwrap_or_else(|_| "transit".to_string());

        // Default to ECDSA P-256
        let key_type = KeyType::EcdsaP256;

        Ok(Self {
            addr,
            token,
            mount_path,
            key_type,
            agent_mode,
        })
    }

    /// Create new configuration
    pub fn new(addr: String, token: String) -> Self {
        Self {
            addr,
            token: Some(token),
            mount_path: "transit".to_string(),
            key_type: KeyType::EcdsaP256,
            agent_mode: false,
        }
    }

    /// Create new configuration for Vault Agent sidecar mode
    /// 
    /// Use this when deploying with Vault Agent in Kubernetes.
    /// The agent will automatically inject authentication tokens.
    pub fn new_agent_mode(addr: String) -> Self {
        Self {
            addr,
            token: None,
            mount_path: "transit".to_string(),
            key_type: KeyType::EcdsaP256,
            agent_mode: true,
        }
    }

    /// Set mount path
    pub fn with_mount_path(mut self, mount_path: String) -> Self {
        self.mount_path = mount_path;
        self
    }

    /// Set key type
    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set Vault address
    pub fn with_addr(mut self, addr: String) -> Self {
        self.addr = addr;
        self
    }

    /// Set Vault token
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self.agent_mode = false;
        self
    }
    
    /// Enable Vault Agent sidecar mode (no token needed)
    pub fn with_agent_mode(mut self, enabled: bool) -> Self {
        self.agent_mode = enabled;
        if enabled {
            self.token = None;
        }
        self
    }
}

impl KeyType {
    /// Convert to Vault key type string
    pub fn to_vault_key_type(&self) -> &'static str {
        match self {
            KeyType::EcdsaP256 => "ecdsa-p256",
            KeyType::Rsa2048 => "rsa-2048",
            KeyType::Rsa4096 => "rsa-4096",
            KeyType::Ed25519 => "ed25519",
        }
    }
}