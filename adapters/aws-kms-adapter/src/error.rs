// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AwsKmsError {
    #[error("AWS KMS service error: {0}")]
    KmsService(#[from] Box<aws_sdk_kms::Error>),
    #[error("AWS configuration error: {0}")]
    Configuration(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Unsupported key usage: {0}")]
    UnsupportedKeyUsage(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Environment variable missing: {0}")]
    MissingEnvVar(String),
    #[error("General KMS error: {0}")]
    General(String),
}

impl From<AwsKmsError> for secret_storage_core::Error {
    fn from(err: AwsKmsError) -> Self {
        match err {
            AwsKmsError::KeyNotFound(id) => secret_storage_core::Error::KeyNotFound(id),
            AwsKmsError::KmsService(e) => {
                secret_storage_core::Error::StoreDisconnected(e.to_string())
            }
            AwsKmsError::Configuration(e) => secret_storage_core::Error::Other(anyhow::anyhow!(e)),
            AwsKmsError::UnsupportedKeyUsage(_e) => secret_storage_core::Error::InvalidOptions,
            AwsKmsError::InvalidKeyFormat(e) => {
                secret_storage_core::Error::Other(anyhow::anyhow!(e))
            }
            AwsKmsError::MissingEnvVar(e) => secret_storage_core::Error::Other(anyhow::anyhow!(
                "Missing environment variable: {}",
                e
            )),
            AwsKmsError::General(e) => secret_storage_core::Error::Other(anyhow::anyhow!(e)),
        }
    }
}
