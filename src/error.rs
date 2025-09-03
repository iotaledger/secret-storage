// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[cfg(not(feature = "std"))]
extern crate alloc;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[cfg(feature = "std")]
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

#[cfg(not(feature = "std"))]
#[derive(Debug, Error)]
pub enum Error {
    #[error("key with ID {0} could not be found")]
    KeyNotFound(alloc::string::String),
    #[error("unable to communicate with key store: {0}")]
    StoreDisconnected(alloc::string::String),
    #[error("failed to generate key with provided options")]
    InvalidOptions,
    #[error("other error: {0}")]
    Other(alloc::string::String),
}
