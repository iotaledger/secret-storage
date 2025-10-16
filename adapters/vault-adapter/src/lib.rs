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
//! - Vault Agent sidecar pattern for Kubernetes deployments
//! - High availability with Vault Enterprise
//! - Audit logging and policy enforcement
//!
//! # Environment Variables
//! - `VAULT_ADDR`: Vault server address (e.g., "http://localhost:8200")
//! - `VAULT_TOKEN`: Vault authentication token (not needed with Vault Agent)
//! - `VAULT_MOUNT_PATH`: Transit mount path (default: "transit")
//! - `VAULT_AGENT_MODE`: Set to "true" to use Vault Agent sidecar (default: "false")
//!
//! # Vault Agent Sidecar Pattern
//!
//! When deploying in Kubernetes, use the Vault Agent sidecar pattern for improved security:
//! 
//! ```bash
//! # App connects to local Vault Agent proxy
//! export VAULT_ADDR="http://127.0.0.1:8100"
//! export VAULT_AGENT_MODE="true"
//! # No VAULT_TOKEN needed - injected automatically by agent
//! ```
//!
//! Benefits:
//! - No long-lived secrets in pods
//! - Automatic token rotation and renewal
//! - Kubernetes ServiceAccount authentication
//! - Reduced attack surface

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