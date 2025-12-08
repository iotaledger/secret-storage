// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// Errors that can occur when using the Vault adapter
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 encoding/decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Vault API error: {0}")]
    Api(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("General error: {0}")]
    General(String),
}

impl From<VaultError> for secret_storage::Error {
    fn from(err: VaultError) -> Self {
        match err {
            VaultError::KeyNotFound(id) => secret_storage::Error::KeyNotFound(id),
            VaultError::Http(e) => {
                secret_storage::Error::StoreDisconnected(e.to_string())
            }
            VaultError::Configuration(e) => secret_storage::Error::Other(anyhow::anyhow!(e)),
            VaultError::Api(ref msg) if msg.contains("404") => {
                secret_storage::Error::KeyNotFound("Key not found in Vault".to_string())
            }
            VaultError::Api(e) => secret_storage::Error::Other(anyhow::anyhow!(e)),
            VaultError::Json(e) => secret_storage::Error::Other(anyhow::anyhow!(
                "JSON serialization error: {}",
                e
            )),
            VaultError::Base64(e) => secret_storage::Error::Other(anyhow::anyhow!(
                "Base64 encoding error: {}",
                e
            )),
            VaultError::Crypto(e) => secret_storage::Error::Other(anyhow::anyhow!(
                "Cryptographic error: {}",
                e
            )),
            VaultError::General(e) => secret_storage::Error::Other(anyhow::anyhow!(e)),
        }
    }
}