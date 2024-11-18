// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("key with ID {0} could not be found")]
    KeyNotFound(String),
    #[error("unable to communicate with key store: {0}")]
    StoreDisconnected(String),
    #[error("failed to generate key with provided options")]
    InvalidOptions,
    #[error(transparent)]
    Other(anyhow::Error),
}
