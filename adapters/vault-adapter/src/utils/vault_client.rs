// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use reqwest::Client;
use serde_json::Value;
use crate::{VaultConfig, VaultError};

/// Vault HTTP client wrapper
pub struct VaultClient {
    client: Client,
    config: VaultConfig,
}

impl VaultClient {
    /// Create new Vault client
    pub fn new(config: VaultConfig) -> Result<Self, VaultError> {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(VaultError::Http)?;

        Ok(Self { client, config })
    }

    /// Make authenticated GET request to Vault
    pub async fn get(&self, path: &str) -> Result<Value, VaultError> {
        let url = format!("{}/v1/{}", self.config.addr, path);
        
        let mut request = self.client.get(&url);
        
        // Only add token header if not using Vault Agent mode
        if let Some(ref token) = self.config.token {
            request = request.header("X-Vault-Token", token);
        }
        
        let response = request
            .send()
            .await
            .map_err(VaultError::Http)?;

        if response.status().is_success() {
            response.json().await.map_err(VaultError::Http)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(VaultError::Api(format!("HTTP {}: {}", status, error_text)))
        }
    }

    /// Make authenticated POST request to Vault
    pub async fn post(&self, path: &str, data: &Value) -> Result<Value, VaultError> {
        let url = format!("{}/v1/{}", self.config.addr, path);
        
        let mut request = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(data);
        
        // Only add token header if not using Vault Agent mode
        if let Some(ref token) = self.config.token {
            request = request.header("X-Vault-Token", token);
        }
        
        let response = request
            .send()
            .await
            .map_err(VaultError::Http)?;

        if response.status().is_success() {
            response.json().await.map_err(VaultError::Http)
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(VaultError::Api(format!("HTTP {}: {}", status, error_text)))
        }
    }

    /// Make authenticated DELETE request to Vault
    pub async fn delete(&self, path: &str) -> Result<(), VaultError> {
        let url = format!("{}/v1/{}", self.config.addr, path);
        
        let mut request = self.client.delete(&url);
        
        // Only add token header if not using Vault Agent mode
        if let Some(ref token) = self.config.token {
            request = request.header("X-Vault-Token", token);
        }
        
        let response = request
            .send()
            .await
            .map_err(VaultError::Http)?;

        if response.status().is_success() || response.status() == 404 {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            Err(VaultError::Api(format!("HTTP {}: {}", status, error_text)))
        }
    }

    /// Get Vault config reference
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }
}