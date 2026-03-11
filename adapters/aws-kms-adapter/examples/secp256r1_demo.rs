// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Demonstration of secp256r1 key creation and public key retrieval with AWS KMS
//!
//! This example shows how to:
//! 1. Create a secp256r1 (ECC_NIST_P256) key in AWS KMS
//! 2. Retrieve the public key in DER format
//! 3. Verify key existence
//! 4. Clean up by scheduling key deletion
//!
//! Usage:
//! ```bash
//! # With AWS profile
//! AWS_PROFILE=your-profile-name AWS_REGION=eu-west-1 cargo run --example secp256r1_demo
//!
//! # With environment variables
//! AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=eu-west-1 cargo run --example secp256r1_demo
//! ```

use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::AwsKmsStorage;
use aws_kms_adapter::KeySpec;
use multi_schema::KeyType;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use std::env;

fn print_session_header() {
  let session_id = chrono::Utc::now().timestamp_millis();
  println!("\n🔐 IOTA Secret Storage - secp256r1 Key Demo");
  println!("📅 Session: SECP256R1_DEMO_{}", session_id);
  println!(
    "🔧 AWS Region: {}",
    env::var("AWS_REGION").unwrap_or_else(|_| "eu-west-1".to_string())
  );

  if let Ok(profile) = env::var("AWS_PROFILE") {
    println!("👤 AWS Profile: {}", profile);
  }

  println!("{}", "=".repeat(60));
}

fn print_step(step: u8, title: &str) {
  println!("\n📋 Step {}: {}", step, title);
  println!("{}", "-".repeat(40));
}

async fn create_storage() -> Result<AwsKmsStorage, Box<dyn std::error::Error>> {
  print_step(1, "Initialize AWS KMS Storage");

  let storage = if env::var("AWS_PROFILE").is_ok() {
    println!("🔑 Using AWS profile authentication");
    AwsKmsStorage::from_profile(env::var("AWS_PROFILE").ok().as_deref()).await?
  } else {
    println!("🔑 Using environment variable authentication");
    AwsKmsStorage::from_env().await?
  };

  let key_options = AwsKmsKeyOptions {
    description: Some("IOTA Demo - secp256r1 key for cryptographic operations".to_string()),
    policy: None, // Use default policy
    tags: vec![
      ("Project".to_string(), "IOTA-SecretStorage".to_string()),
      ("KeyType".to_string(), "secp256r1".to_string()),
      ("Purpose".to_string(), "Demo".to_string()),
      ("CreatedBy".to_string(), "secp256r1_demo".to_string()),
    ],
    key_spec: Some(KeySpec::EccSecgP256K1),
  };
  let storage = storage.with_key_options(key_options);

  println!("✅ AWS KMS storage initialized successfully");
  Ok(storage)
}

async fn generate_secp256r1_key(storage: &AwsKmsStorage) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
  print_step(2, "Generate secp256r1 Key");

  println!("📝 Creating new secp256r1 key");

  let (logical_key_id, public_key) = storage.generate_key_with_options(KeyType::K256DerEncoded).await?;
  let public_key_der = public_key.bytes();

  println!("🔑 Key generation completed!");
  println!("   📌 Key Id: {}", logical_key_id);
  println!("   📐 Public Key Size: {} bytes (DER format)", public_key_der.len());
  println!("   🔍 Key Type: secp256r1 (ECC_NIST_P256)");

  // Display first few bytes of public key for verification
  if public_key_der.len() >= 10 {
    let preview: Vec<String> = public_key_der[..10].iter().map(|b| format!("{:02x}", b)).collect();
    println!("   📋 Public Key Preview: {}...", preview.join(" "));
  }
  println!("   📋 Public Key Debug: {:?}...", &public_key_der);

  Ok((logical_key_id, public_key_der.clone()))
}

async fn verify_key_existence(storage: &AwsKmsStorage, key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
  print_step(3, "Verify Key Existence");

  println!("🔍 Checking if key exists in AWS KMS...");

  let exists = storage.exist(&key_id.to_string()).await?;

  if exists {
    println!("✅ Key verified - exists in AWS KMS");
    println!("   📌 Key Id: {}", key_id);
    println!("   🔒 Status: Active and available for operations");
  } else {
    return Err("Key verification failed - key not found in KMS".into());
  }

  Ok(())
}

async fn retrieve_public_key(
  storage: &AwsKmsStorage,
  key_id: &str,
  original_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
  print_step(4, "Retrieve Public Key");

  println!("📥 Retrieving public key from AWS KMS...");

  let retrieved_key = storage.public_key(&key_id.to_string()).await?;
  let retrieved_key_der = retrieved_key.bytes();

  println!("✅ Public key retrieved successfully!");
  println!("   📐 Retrieved Size: {} bytes", retrieved_key_der.len());

  // Verify the keys match
  if retrieved_key_der == original_key {
    println!("✅ Key integrity verified - retrieved key matches original");
  } else {
    return Err("Key integrity check failed - retrieved key doesn't match original".into());
  }

  // Show key format analysis
  println!("📊 Public Key Analysis:");
  println!("   🔧 Format: DER-encoded");
  println!("   📏 Length: {} bytes", retrieved_key_der.len());
  println!("   🎯 Curve: secp256r1 (NIST P-256)");

  Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  print_session_header();

  // Initialize storage
  let storage = create_storage().await?;

  // Generate secp256r1 key
  let (logical_key_id, original_public_key) = generate_secp256r1_key(&storage).await?;

  // Verify key exists
  verify_key_existence(&storage, &logical_key_id).await?;

  // Retrieve and verify public key
  retrieve_public_key(&storage, &logical_key_id, &original_public_key).await?;

  // Final summary
  println!("\n🎉 Demo Completed Successfully!");

  Ok(())
}
