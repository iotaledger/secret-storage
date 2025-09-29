// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! HashiCorp Vault adapter for secret-storage core traits
//!
//! This adapter provides integration with HashiCorp Vault for enterprise-grade 
//! key management with centralized secret management and fine-grained access control.
//!
//! # Features
//! - Minimal environment variable configuration
//! - Native integration with Vault's authentication methods
//! - Support for Vault's Transit secrets engine for cryptographic operations
//! - High availability with Vault Enterprise
//! - Audit logging and policy enforcement
//!
//! # Environment Variables
//! - `VAULT_ADDR`: Vault server address (e.g., "http://localhost:8200")
//! - `VAULT_TOKEN`: Vault authentication token
//! - `VAULT_MOUNT_PATH`: Transit mount path (default: "transit")

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