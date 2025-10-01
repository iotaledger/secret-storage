// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Key generation utilities

use std::time::{SystemTime, UNIX_EPOCH};
use std::error::Error;
use secret_storage_core::KeyGenerate;
use aws_kms_adapter::{AwsKmsKeyOptions, AwsKmsStorage};

/// Generate a dynamic key alias with timestamp in the format: kms-demo-{timestamp}
pub fn generate_key_alias() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("kms-demo-{}", timestamp)
}

/// Generate a new AWS KMS key with specified alias and return the key ID and public key
pub async fn generate_dynamic_key(
    storage: &AwsKmsStorage,
    alias: String,
) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    let options = AwsKmsKeyOptions {
        description: Some("IOTA KMS Demo Key - ECDSA P-256".to_string()),
        policy: None,
        alias: Some(alias),
        tags: vec![
            ("Project".to_string(), "IOTA-SecretStorage".to_string()),
            ("KeyType".to_string(), "secp256r1".to_string()),
            ("Purpose".to_string(), "IOTADemo".to_string()),
            ("CreatedBy".to_string(), "iota_kms_demo".to_string()),
        ],
    };

    let (key_id, public_key) = storage.generate_key_with_options(options).await?;
    Ok((key_id, public_key))
}
