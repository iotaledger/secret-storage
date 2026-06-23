// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! AWS KMS adapter for secret-storage core traits
//!
//! This adapter provides integration with AWS Key Management Service (KMS) for
//! enterprise-grade key management with hardware security modules and centralized governance.
//!
//! # Features
//! - Minimal environment variable configuration
//! - Native integration with AWS IAM for fine-grained access control
//! - Support for key rotation and audit logging via CloudTrail
//! - High availability with AWS SLA
//! - FIPS 140-2 Level 3 HSM protection
//!
//! # Environment Variables
//! - `AWS_ACCESS_KEY_ID`: AWS access key
//! - `AWS_SECRET_ACCESS_KEY`: AWS secret key
//! - `AWS_REGION`: AWS region
//! - `KMS_KEY_ID`: Optional, for using existing keys

mod config;
mod error;
mod signer;
mod storage;
mod utils;

pub use config::*;
pub use error::*;
pub use signer::*;
pub use storage::*;
pub use utils::*;

pub mod typed_key_signature;
