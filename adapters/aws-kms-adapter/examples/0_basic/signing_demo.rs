// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Demonstration of message signing functionality with AWS KMS
//!
//! This example shows how to:
//! 1. Create a secp256r1 key with AWS KMS
//! 2. Get a signer instance for the key
//! 3. Sign a message using the signer
//! 4. Verify the signature process
//! 5. Clean up by scheduling key deletion
//!
//! Usage:
//! ```bash
//! # With AWS profile
//! AWS_PROFILE=your-profile-name AWS_REGION=eu-west-1 cargo run --example signing_demo
//!
//! # With environment variables
//! AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=eu-west-1 cargo run --example signing_demo
//! ```

use aws_kms_adapter::AwsKmsKeyOptions;
use aws_kms_adapter::AwsKmsStorage;
use aws_kms_adapter::KeySpec;
use typed_key_signature::KeyType;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions;
use secret_storage::Signer;
use std::env;

fn print_session_header() {
  let session_id = chrono::Utc::now().timestamp_millis();
  println!("\n🔐 IOTA Secret Storage - Message Signing Demo");
  println!("📅 Session: SIGNING_DEMO_{}", session_id);
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

  // Add options to support creating new keys and signing
  let key_options = AwsKmsKeyOptions {
    description: Some("IOTA Demo - secp256r1 key for message signing".to_string()),
    policy: None,
    tags: vec![
      ("Project".to_string(), "IOTA-SecretStorage".to_string()),
      ("KeyType".to_string(), "secp256r1".to_string()),
      ("Purpose".to_string(), "SigningDemo".to_string()),
      ("CreatedBy".to_string(), "signing_demo".to_string()),
    ],
    key_spec: Some(KeySpec::EccNistP256),
  };
  let storage = storage.with_key_options(key_options);

  println!("✅ AWS KMS storage initialized successfully");
  Ok(storage)
}

async fn generate_signing_key(storage: &AwsKmsStorage) -> Result<String, Box<dyn std::error::Error>> {
  print_step(2, "Generate Signing Key");

  println!("📝 Creating new secp256r1 signing key...");

  let (key_id, public_key_der) = storage.generate_key_with_options(KeyType::Secp256r1DerEncoded).await?;

  println!("🔑 Key generation completed!");
  println!("   📌 Key Id: {}", key_id);
  println!(
    "   📐 Public Key Size: {} bytes (DER format)",
    public_key_der.bytes().len()
  );
  println!("   🔍 Key Type: secp256r1 (ECC_NIST_P256)");

  Ok(key_id)
}

async fn demonstrate_signing(storage: &AwsKmsStorage, key_id: &str) -> Result<(), Box<dyn std::error::Error>> {
  print_step(3, "Message Signing Demonstration");

  // Prepare test messages with proper lifetimes
  let message1 = "Hello, IOTA Secret Storage!".as_bytes().to_vec();
  let message2 = "Short msg".as_bytes().to_vec();
  let message3 = "This is a longer message that we want to sign using AWS KMS and secp256r1 elliptic curve cryptography. The signature will be generated securely within the AWS KMS hardware security module.".as_bytes().to_vec();
  let message4 = vec![0u8; 32]; // 32 bytes of zeros (common for hash inputs)
  let message5 = (0..=255).collect::<Vec<u8>>(); // Sequential bytes 0-255

  let test_messages = [&message1, &message2, &message3, &message4, &message5];

  println!("📝 Getting signer instance for key: {}", key_id);
  let key_string = key_id.to_string();
  let signer = storage.get_signer_with_options(&key_string, &KeyType::Secp256r1DerEncoded)?;

  println!("🔍 Signer created successfully!");
  println!("   📌 Signer Key ID: {}", signer.key_id());

  for (i, message) in test_messages.iter().enumerate() {
    println!("\n🔐 Signing Test Message #{}", i + 1);
    println!("   📏 Message Size: {} bytes", message.len());

    // Display message preview (first 50 bytes or entire message if shorter)
    if message.len() <= 50 {
      if message.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        println!("   📄 Content: \"{}\"", String::from_utf8_lossy(message));
      } else {
        println!("   📄 Content (hex): {}", hex::encode(message));
      }
    } else {
      let preview = &message[..50];
      if preview.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        println!("   📄 Content: \"{}...\"", String::from_utf8_lossy(preview));
      } else {
        println!("   📄 Content (hex): {}...", hex::encode(preview));
      }
    }

    // Perform signing
    println!("   🔏 Signing with AWS KMS...");
    let signature = signer.sign(&(*message).clone()).await?;
    let signature_bytes = signature.bytes();

    println!("   ✅ Signature Generated!");
    println!("      📏 Signature Size: {} bytes", signature_bytes.len());
    println!(
      "      🔍 Signature (hex): {}",
      hex::encode(&signature_bytes[..std::cmp::min(32, signature_bytes.len())])
    );
    if signature_bytes.len() > 32 {
      println!("      ... (showing first 32 bytes)");
    }

    // Verify signature is not empty and has reasonable length
    if signature_bytes.is_empty() {
      return Err("Generated signature is empty!".into());
    }

    if signature_bytes.len() < 64 || signature_bytes.len() > 256 {
      println!("      ⚠️ Warning: Unusual signature length for secp256r1");
    }
  }

  println!("\n🎉 All signing tests completed successfully!");

  Ok(())
}

async fn demonstrate_signer_public_key(
  storage: &AwsKmsStorage,
  key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
  print_step(4, "Signer Public Key Retrieval");

  println!("📝 Getting signer instance for key: {}", key_id);
  let key_string = key_id.to_string();
  let signer = storage.get_signer_with_options(&key_string, &KeyType::Secp256r1DerEncoded)?;

  println!("🔍 Retrieving public key via signer...");
  let public_key_from_signer = signer.public_key().await?;
  let public_key_from_signer_bytes = public_key_from_signer.bytes();

  println!("✅ Public key retrieved via signer!");
  println!("   📏 Size: {} bytes", public_key_from_signer_bytes.len());

  // Compare with direct storage retrieval
  println!("🔍 Comparing with direct storage retrieval...");
  let public_key_from_storage = storage.public_key(&key_string).await?;
  let public_key_from_storage = public_key_from_storage.bytes();

  if public_key_from_signer_bytes == public_key_from_storage {
    println!("✅ Public keys match - signer and storage return identical keys!");
  } else {
    return Err("Public key mismatch between signer and storage!".into());
  }

  Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  print_session_header();

  // Initialize storage
  let storage = create_storage().await?;

  // Generate signing key
  let key_id = generate_signing_key(&storage).await?;

  // Demonstrate signing functionality
  demonstrate_signing(&storage, &key_id).await?;

  // Demonstrate signer public key retrieval
  demonstrate_signer_public_key(&storage, &key_id).await?;

  // Note: Key cleanup is commented out to avoid accidental deletion during development
  // Uncomment the following line if you want to schedule the key for deletion:
  // cleanup_key(&storage, &key_id).await?;

  // Final summary
  println!("\n🎉 Message Signing Demo Completed!");
  println!("{}", "=".repeat(60));
  println!("✅ Created secp256r1 key in AWS KMS");
  println!("✅ Generated signer instance successfully");
  println!("✅ Signed multiple test messages");
  println!("✅ Verified signer public key retrieval");
  println!("🔑 Key preserved for further testing (deletion commented out)");

  println!("\n💡 Key Features Demonstrated:");
  println!("  • AWS KMS secp256r1 key generation with custom options");
  println!("  • Signer instance creation from storage");
  println!("  • Message signing with various data types and sizes");
  println!("  • Public key retrieval through signer interface");
  println!("  • Proper key lifecycle management");

  println!("\n🔐 Security Notes:");
  println!("  • Private keys never leave AWS KMS hardware security modules");
  println!("  • All signing operations are performed within AWS KMS");
  println!("  • Signatures are generated using ECDSA with SHA-256");
  println!("  • Full audit trail available through AWS CloudTrail");

  Ok(())
}
