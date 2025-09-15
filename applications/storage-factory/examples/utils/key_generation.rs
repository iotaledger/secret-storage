// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Key generation utilities

use secret_storage_core::{KeyGenerate, KeyGet};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a dynamic key alias with timestamp in the format: aws-kms-demo-{timestamp}
pub fn generate_key_alias() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("aws-kms-demo-{}", timestamp)
}

/// Generate a new key with specified alias and return normalized alias and public key
pub async fn generate_dynamic_key<T>(storage: &T, alias: String) -> Result<(String, Vec<u8>), Box<dyn Error>>
where
    T: KeyGenerate<aws_kms_adapter::AwsKmsSignatureScheme, String, Options = aws_kms_adapter::AwsKmsKeyOptions>
        + KeyGet<aws_kms_adapter::AwsKmsSignatureScheme, String>
        + Sync,
{
    // Create options with the specified alias
    let options = aws_kms_adapter::AwsKmsKeyOptions {
        alias: Some(alias),
        description: Some("IOTA KMS Demo Key".to_string()),
        policy: None,
        tags: vec![],
    };
    
    // Generate key with specified alias
    let (key_id, public_key) = storage.generate_key_with_options(options).await?;
    Ok((key_id, public_key))
}
