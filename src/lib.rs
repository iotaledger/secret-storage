// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
extern crate alloc;

mod error;
mod signature_scheme;
mod signer;
mod storage;

pub use error::*;
pub use signature_scheme::*;
pub use signer::*;
pub use storage::*;
