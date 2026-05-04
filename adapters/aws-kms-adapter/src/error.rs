// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AwsKmsError {
  #[error("AWS KMS service error: {0}")]
  KmsService(#[from] Box<aws_sdk_kms::Error>),
  #[error("AWS configuration error: {0}")]
  Configuration(String),
  #[error("Key not found: {0}")]
  KeyNotFound(String),
  #[error("Unsupported key type: {0}")]
  UnsupportedKeyType(String),
  #[error("Unsupported key usage: {0}")]
  UnsupportedKeyUsage(String),
  #[error("Invalid key format: {0}")]
  InvalidKeyFormat(String),
  #[error("Invalid signing algorithm format: {0}")]
  InvalidSigningAlgorithmFormat(String),
  #[error("Environment variable missing: {0}")]
  MissingEnvVar(String),
  #[error("General KMS error: {0}")]
  General(String),
}

impl From<AwsKmsError> for secret_storage::Error {
  fn from(err: AwsKmsError) -> Self {
    match err {
      AwsKmsError::KeyNotFound(id) => secret_storage::Error::KeyNotFound(id),
      AwsKmsError::KmsService(e) => secret_storage::Error::StoreDisconnected(e.to_string()),
      AwsKmsError::Configuration(e) => secret_storage::Error::Other(anyhow!(e)),
      AwsKmsError::UnsupportedKeyType(e) => secret_storage::Error::Other(anyhow!(e)),
      AwsKmsError::UnsupportedKeyUsage(_) => secret_storage::Error::InvalidOptions,
      AwsKmsError::InvalidKeyFormat(e) => secret_storage::Error::Other(anyhow!(e)),
      AwsKmsError::InvalidSigningAlgorithmFormat(e) => secret_storage::Error::Other(anyhow!(e)),
      AwsKmsError::MissingEnvVar(e) => {
        secret_storage::Error::Other(anyhow!("Missing environment variable: {}", e))
      }
      AwsKmsError::General(e) => secret_storage::Error::Other(anyhow!(e)),
    }
  }
}
