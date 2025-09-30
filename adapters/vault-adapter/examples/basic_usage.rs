// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Basic usage example for the HashiCorp Vault adapter
//!
//! This example demonstrates:
//! 1. Creating a Vault storage instance
//! 2. Generating a new signing key
//! 3. Getting the public key
//! 4. Creating a signer and signing data
//! 5. Cleaning up the key
//!
//! Prerequisites:
//! - HashiCorp Vault server running (use docker-compose.yml)
//! - Transit secrets engine enabled
//! - Valid Vault token
//!
//! Usage:
//! ```bash
//! # Start Vault with docker-compose (see scripts/vault-dev.sh)
//! ./scripts/vault-dev.sh
//!
//! # Set environment variables
//! export VAULT_ADDR="http://localhost:8200"
//! export VAULT_TOKEN="dev-token"
//! export VAULT_MOUNT_PATH="transit"
//!
//! # Run the example
//! VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-token VAULT_MOUNT_PATH="transit" cargo run --package vault-adapter --example basic_usage
//! ```

use secret_storage_core::{KeyDelete, KeyGenerate, KeyGet, KeySign, Signer};
use std::env;
use vault_adapter::{VaultKeyOptions, VaultStorage};

fn print_session_header() {
    let session_id = chrono::Utc::now().timestamp_millis();
    println!("\n🔐 IOTA Secret Storage - Vault Basic Usage");
    println!("📅 Session: VAULT_BASIC_{}", session_id);
    println!(
        "🔧 Vault Address: {}",
        env::var("VAULT_ADDR").unwrap_or_else(|_| "http://localhost:8200".to_string())
    );
    println!("{}", "=".repeat(60));
}

fn print_step(step: u8, title: &str) {
    println!("\n📋 Step {}: {}", step, title);
    println!("{}", "-".repeat(40));
}

async fn create_storage() -> Result<VaultStorage, Box<dyn std::error::Error>> {
    print_step(1, "Initialize Vault Storage");

    println!("🔑 Using environment variable authentication");
    let storage = VaultStorage::from_env().await?;

    println!("✅ Vault storage initialized successfully");
    Ok(storage)
}

async fn generate_key(storage: &VaultStorage) -> Result<String, Box<dyn std::error::Error>> {
    print_step(2, "Generate Signing Key");

    let session_id = chrono::Utc::now().timestamp_millis();
    let key_name = format!("iota-demo-{}", session_id);

    println!("📝 Creating new ECDSA P-256 signing key...");

    let options = VaultKeyOptions {
        description: Some("IOTA Demo - ECDSA P-256 key for signing".to_string()),
        key_name: Some(key_name.clone()),
    };

    let (logical_key_id, public_key_der) = storage.generate_key_with_options(options).await?;

    println!("🔑 Key generation completed!");
    println!("   📌 Key Name: {}", logical_key_id);
    println!(
        "   📐 Public Key Size: {} bytes (DER format)",
        public_key_der.len()
    );
    println!("   🔍 Key Type: ECDSA P-256");

    Ok(logical_key_id)
}

async fn demonstrate_signing(
    storage: &VaultStorage,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    print_step(3, "Message Signing Demonstration");

    let message = "Hello, IOTA Secret Storage with Vault!".as_bytes().to_vec();

    println!("📝 Getting signer instance for key: {}", key_id);
    let key_string = key_id.to_string();
    let signer = storage.get_signer(&key_string)?;

    println!("🔍 Signer created successfully!");
    println!("   📌 Signer Key ID: {}", signer.key_id());

    println!("\n🔐 Signing message...");
    println!("   📄 Message: \"{}\"", String::from_utf8_lossy(&message));
    println!("   📏 Message Size: {} bytes", message.len());

    let signature = signer.sign(&message).await?;

    println!("   ✅ Signature Generated!");
    println!("      📏 Signature Size: {} bytes", signature.len());
    println!(
        "      🔍 Signature (hex): {}",
        hex::encode(&signature[..std::cmp::min(32, signature.len())])
    );
    if signature.len() > 32 {
        println!("      ... (showing first 32 bytes)");
    }

    Ok(())
}

async fn demonstrate_public_key(
    storage: &VaultStorage,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    print_step(4, "Public Key Retrieval");

    println!("🔍 Retrieving public key for key: {}", key_id);
    let key_string = key_id.to_string();
    let public_key = storage.public_key(&key_string).await?;

    println!("✅ Public key retrieved!");
    println!("   📏 Size: {} bytes", public_key.len());
    println!(
        "   🔍 Public Key (hex): {}",
        hex::encode(&public_key[..std::cmp::min(32, public_key.len())])
    );
    if public_key.len() > 32 {
        println!("      ... (showing first 32 bytes)");
    }

    Ok(())
}

async fn cleanup_key(
    storage: &VaultStorage,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    print_step(5, "Key Cleanup");

    println!("🗑️ Deleting key: {}", key_id);
    let key_string = key_id.to_string();
    storage.delete(&key_string).await?;

    println!("✅ Key deleted successfully");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_session_header();

    // Initialize storage
    let storage = create_storage().await?;

    // Generate signing key
    let key_id = generate_key(&storage).await?;

    // Demonstrate public key retrieval
    demonstrate_public_key(&storage, &key_id).await?;

    // Demonstrate signing functionality
    demonstrate_signing(&storage, &key_id).await?;

    // Cleanup
    cleanup_key(&storage, &key_id).await?;

    // Final summary
    println!("\n🎉 Vault Basic Usage Demo Completed!");
    println!("{}", "=".repeat(60));
    println!("✅ Created ECDSA P-256 key in Vault");
    println!("✅ Retrieved public key successfully");
    println!("✅ Generated signer instance successfully");
    println!("✅ Signed test message");
    println!("✅ Cleaned up key");

    println!("\n💡 Key Features Demonstrated:");
    println!("  • Vault ECDSA P-256 key generation");
    println!("  • Signer instance creation from storage");
    println!("  • Message signing with Vault Transit engine");
    println!("  • Public key retrieval in DER format");
    println!("  • Proper key lifecycle management");

    println!("\n🔐 Security Notes:");
    println!("  • Private keys never leave Vault's secure storage");
    println!("  • All signing operations are performed within Vault");
    println!("  • Signatures are generated using ECDSA with P-256 curve");
    println!("  • Full audit trail available through Vault audit logs");

    Ok(())
}
