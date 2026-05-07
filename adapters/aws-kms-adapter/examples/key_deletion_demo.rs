// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Demonstration of key deletion functionality with AWS KMS
//!
//! This example shows how to:
//! 1. Create keys
//! 2. Delete keys using both KMS key IDs
//! 3. Handle the AWS KMS deletion process correctly
//!
//! Usage:
//! ```bash
//! AWS_PROFILE=your-profile-name AWS_REGION=eu-west-1 cargo run --example key_deletion_demo
//! ```

use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::AwsKmsStorage;
use aws_kms_adapter::KeySpec;
use multi_signature_scheme::KeyType;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use std::env;

fn print_header() {
  println!("\n🗑️ AWS KMS Key Deletion Demo");
  println!("{}", "=".repeat(50));
  println!("This demo shows deletion of keys");
  println!();
}

async fn create_test_key(storage: &AwsKmsStorage) -> Result<String, Box<dyn std::error::Error>> {
  let (kms_key_id, _public_key) = storage.generate_key_with_options(KeyType::P256DerEncoded).await?;

  println!("✅ Created key:");
  println!("   KMS Key ID: {}", kms_key_id);

  Ok(kms_key_id)
}

async fn demo_kms_id_deletion(storage: &AwsKmsStorage) -> Result<(), Box<dyn std::error::Error>> {
  println!("\n📋 Demo 1: Deletion via KMS Key ID");
  println!("{}", "-".repeat(30));

  let key_id = create_test_key(storage).await?;

  println!("\n🗑️ Deleting key via KMS key ID...");
  storage.delete(&key_id).await?;

  println!("✅ Deletion via KMS key ID completed");
  println!("   KMS key scheduled for deletion: {}", key_id);

  Ok(())
}

async fn demo_verification(storage: &AwsKmsStorage) -> Result<(), Box<dyn std::error::Error>> {
  println!("\n📋 Demo 2: Verification After Deletion");
  println!("{}", "-".repeat(30));

  // Create a key we'll verify deletion for
  let key_id = create_test_key(storage).await?;

  // Verify it exists before deletion
  let exists_before = storage.exist(&key_id).await?;
  println!("🔍 Key exists before deletion: {}", exists_before);

  // Delete it
  storage.delete(&key_id).await?;

  // Wait a moment and check again
  println!("⏳ Checking existence after deletion...");
  let exists_after = storage.exist(&key_id).await?;
  println!("🔍 Key exists after deletion: {}", exists_after);

  if !exists_after {
    println!("✅ Key properly marked as non-existent after deletion");
  } else {
    println!("⚠️ Key still shows as existing (this is normal during the waiting period)");
  }

  Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  print_header();

  // Initialize storage
  let storage = if env::var("AWS_PROFILE").is_ok() {
    println!("🔑 Using AWS profile authentication");
    AwsKmsStorage::from_profile(env::var("AWS_PROFILE").ok().as_deref()).await?
  } else {
    println!("🔑 Using environment variable authentication");
    AwsKmsStorage::from_env().await?
  };

  // Add options to support creating new keys and signing
  let key_options = AwsKmsKeyOptions {
    description: Some("Test key for deletion demo".to_string()),
    policy: None,
    tags: vec![
      ("Purpose".to_string(), "DeletionDemo".to_string()),
      ("Temporary".to_string(), "true".to_string()),
    ],
    key_spec: Some(KeySpec::EccNistP256),
  };
  let storage = storage.with_key_options(key_options);

  // Run deletion demos
  demo_kms_id_deletion(&storage).await?;
  demo_verification(&storage).await?;

  // Final summary
  println!("\n🎉 Key Deletion Demo Completed!");
  println!("{}", "=".repeat(50));
  println!("✅ Demonstrated deletion via KMS key ID");
  println!("✅ Showed verification after deletion");

  println!("\n💡 Key Points:");
  println!("  • AWS KMS requires 7-30 day waiting period for deletion");
  println!("  • Key deletion can be cancelled during waiting period");

  println!("\n⚠️ Important:");
  println!("  Check your AWS KMS console to see scheduled deletions");
  println!("  Cancel any test key deletions if you want to keep them");

  Ok(())
}
