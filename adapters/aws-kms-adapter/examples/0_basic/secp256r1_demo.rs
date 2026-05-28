// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Demonstrates secp256r1 key creation and public key retrieval with AWS KMS.
//!
//! Usage:
//! ```
//! AWS_PROFILE=<profile> AWS_REGION=<region> cargo run --example secp256r1_demo
//! AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret> AWS_REGION=<region> cargo run --example secp256r1_demo
//! ```

use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::AwsKmsStorage;
use aws_kms_adapter::KeySpec;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use typed_key_signature::KeyType;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = if let Some(profile) = env::var("AWS_PROFILE").ok() {
        AwsKmsStorage::from_profile(Some(&profile)).await?
    } else {
        AwsKmsStorage::from_env().await?
    };
    let storage = base.with_key_options(AwsKmsKeyOptions {
        description: Some("IOTA Demo - secp256r1 key".to_string()),
        policy: None,
        tags: vec![
            ("Project".to_string(), "IOTA-SecretStorage".to_string()),
            ("Purpose".to_string(), "Demo".to_string()),
        ],
        key_spec: Some(KeySpec::EccNistP256),
    });

    println!("Generating secp256r1 key...");
    let (key_id, public_key) = storage.generate_key_with_options(KeyType::Secp256r1DerEncoded).await?;
    println!("Key ID: {key_id}");
    println!("Public key: {} bytes (DER)", public_key.bytes().len());

    let exists = storage.exist(&key_id).await?;
    println!("Key exists: {exists}");

    let retrieved = storage.public_key(&key_id).await?;
    if retrieved.bytes() == public_key.bytes() {
        println!("Public key integrity verified.");
    } else {
        return Err("Public key mismatch between generate and retrieve".into());
    }

    Ok(())
}
