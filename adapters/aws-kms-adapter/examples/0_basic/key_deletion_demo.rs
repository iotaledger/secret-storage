// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Demonstrates key deletion with AWS KMS.
//!
//! Note: AWS KMS requires a 7-30 day waiting period before keys are permanently deleted.
//! Keys can be cancelled during this period via the AWS console.
//!
//! Usage:
//! ```
//! AWS_PROFILE=<profile> AWS_REGION=<region> cargo run --example key_deletion_demo
//! ```

use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::KeySpec;
use examples::create_storage;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use typed_key_signature::KeyType;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let storage = create_storage().await?.with_key_options(AwsKmsKeyOptions {
    description: Some("Test key for deletion demo".to_string()),
    policy: None,
    tags: vec![("Purpose".to_string(), "DeletionDemo".to_string())],
    key_spec: Some(KeySpec::EccNistP256),
  });

  // Demo 1: schedule deletion via KMS key ID
  let (key_id, _) = storage.generate_key_with_options(KeyType::Secp256r1).await?;
  println!("Created key: {key_id}");
  storage.delete(&key_id).await?;
  println!("Deletion scheduled for: {key_id}");

  // Demo 2: verify exist() reflects deletion
  let (key_id2, _) = storage.generate_key_with_options(KeyType::Secp256r1).await?;
  println!("Created key: {key_id2}");
  println!("Exists before deletion: {}", storage.exist(&key_id2).await?);
  storage.delete(&key_id2).await?;
  println!("Exists after deletion: {}", storage.exist(&key_id2).await?);

  Ok(())
}
