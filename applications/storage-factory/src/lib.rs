// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Storage factory with builder pattern for adapter selection
//!
//! This crate provides a convenient builder pattern for selecting and configuring
//! different secret storage adapters based on requirements and available configuration.
//!
//! # Example
//! ```rust,no_run
//! use storage_factory::StorageBuilder;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Explicit AWS KMS configuration
//!     let aws_storage = StorageBuilder::new()
//!         .aws_kms()
//!         .with_region("us-east-1".to_string())
//!         .build_aws_kms()
//!         .await?;
//!
//!     // Future: Passkey adapter
//!     // let passkey_storage = StorageBuilder::new()
//!     //     .passkey()
//!     //     .build_passkey()
//!     //     .await?;
//!     
//!     Ok(())
//! }
//! ```

mod builder;
mod error;

pub use builder::*;
pub use error::*;