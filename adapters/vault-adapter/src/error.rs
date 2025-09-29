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

impl From<VaultError> for secret_storage_core::Error {
    fn from(err: VaultError) -> Self {
        secret_storage_core::Error::Other(anyhow::Error::new(err))
    }
}