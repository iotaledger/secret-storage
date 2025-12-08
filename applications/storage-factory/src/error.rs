// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageFactoryError {
    #[error("No suitable adapter found for current configuration")]
    NoAdapterFound,
    #[error("Required environment variables not set: {0}")]
    MissingConfiguration(String),
    #[error("Adapter initialization failed: {0}")]
    AdapterInitialization(String),
    #[error("Unsupported storage type: {0}")]
    UnsupportedStorageType(String),
}

impl From<StorageFactoryError> for secret_storage::Error {
    fn from(err: StorageFactoryError) -> Self {
        secret_storage::Error::Other(anyhow::anyhow!(err))
    }
}