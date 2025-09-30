// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Comprehensive signing demonstration with HashiCorp Vault
//!
//! This example shows advanced signing scenarios:
//! 1. Creating multiple keys with different configurations
//! 2. Signing various types of data
//! 3. Demonstrating error handling
//! 4. Performance testing with multiple signatures
//!
//! Prerequisites:
//! - HashiCorp Vault server running
//! - Transit secrets engine enabled
//! - Valid Vault token
//!
//! Usage:
//! ```bash
//! # Start Vault with docker-compose
//! ./scripts/vault-dev.sh
//!
//! # Set environment variables  
//! export VAULT_ADDR="http://localhost:8200"
//! export VAULT_TOKEN="dev-token"
//! export VAULT_MOUNT_PATH="transit"
//!
//! # Run the demo
//! VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-token VAULT_MOUNT_PATH="transit" cargo run --package vault-adapter --example signing_demo
//! ```

use secret_storage_core::{KeyDelete, KeyExist, KeyGenerate, KeySign, Signer};
use std::env;
use std::time::Instant;
use vault_adapter::{VaultKeyOptions, VaultStorage};

fn print_session_header() {
    let session_id = chrono::Utc::now().timestamp_millis();
    println!("\n🔐 IOTA Secret Storage - Vault Signing Demo");
    println!("📅 Session: VAULT_SIGNING_{}", session_id);
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

    let storage = VaultStorage::from_env().await?;
    println!("✅ Vault storage initialized successfully");
    Ok(storage)
}

async fn generate_multiple_keys(
    storage: &VaultStorage,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    print_step(2, "Generate Multiple Keys");

    let session_id = chrono::Utc::now().timestamp_millis();
    let mut key_ids = Vec::new();

    // Generate 3 different keys for testing
    for i in 1..=3 {
        let key_name = format!("signing-demo-{}-key-{}", session_id, i);

        println!("📝 Creating key #{}: {}", i, key_name);

        let options = VaultKeyOptions {
            description: Some(format!("IOTA Signing Demo Key #{} - ECDSA P-256", i)),
            key_name: Some(key_name.clone()),
        };

        let (logical_key_id, public_key_der) = storage.generate_key_with_options(options).await?;

        println!("   ✅ Key created: {}", logical_key_id);
        println!("   📏 Public key size: {} bytes", public_key_der.len());

        key_ids.push(logical_key_id);
    }

    println!("\n🎉 All {} keys generated successfully!", key_ids.len());
    Ok(key_ids)
}

async fn test_key_existence(
    storage: &VaultStorage,
    key_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    print_step(3, "Test Key Existence");

    for key_id in key_ids {
        println!("🔍 Checking existence of key: {}", key_id);
        let exists = storage.exist(key_id).await?;

        if exists {
            println!("   ✅ Key exists");
        } else {
            return Err(format!("Key {} should exist but doesn't!", key_id).into());
        }
    }

    // Test non-existent key
    let fake_key = "non-existent-key-12345";
    println!("🔍 Checking non-existent key: {}", fake_key);
    let exists = storage.exist(&fake_key.to_string()).await?;

    if !exists {
        println!("   ✅ Correctly identified non-existent key");
    } else {
        return Err("Non-existent key incorrectly reported as existing!".into());
    }

    Ok(())
}

async fn comprehensive_signing_test(
    storage: &VaultStorage,
    key_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    print_step(4, "Comprehensive Signing Tests");

    // Test different types of data
    let test_data = vec![
        ("Empty data", vec![]),
        ("Short message", "Hello Vault!".as_bytes().to_vec()),
        ("Unicode text", "🔐 IOTA 🌍 世界".as_bytes().to_vec()),
        (
            "Binary data",
            vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD],
        ),
        ("Large data", vec![0x42; 1024]), // 1KB of 0x42
        ("Hash-like data", (0..32).map(|i| i as u8).collect()), // 32 bytes sequential
    ];

    for (i, key_id) in key_ids.iter().enumerate() {
        println!("\n🔑 Testing with Key #{}: {}", i + 1, key_id);

        let key_string = key_id.to_string();
        let signer = storage.get_signer(&key_string)?;
        println!("   📝 Signer created for key: {}", signer.key_id());

        for (desc, data) in &test_data {
            println!("\n   🔐 Signing: {}", desc);
            println!("      📏 Data size: {} bytes", data.len());

            if data.len() <= 20 && data.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
                println!("      📄 Content: \"{}\"", String::from_utf8_lossy(data));
            } else if data.len() <= 20 {
                println!("      📄 Content (hex): {}", hex::encode(data));
            } else {
                println!("      📄 Content: [binary data, {} bytes]", data.len());
            }

            let start = Instant::now();
            let signature = signer.sign(data).await?;
            let duration = start.elapsed();

            println!("      ✅ Signed in {:?}", duration);
            println!("      📏 Signature size: {} bytes", signature.len());

            if signature.is_empty() {
                return Err("Generated signature is empty!".into());
            }
        }
    }

    Ok(())
}

async fn performance_test(
    storage: &VaultStorage,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    print_step(5, "Performance Testing");

    let key_string = key_id.to_string();
    let signer = storage.get_signer(&key_string)?;
    let test_message = "Performance test message for IOTA Vault adapter"
        .as_bytes()
        .to_vec();

    println!("🚀 Running performance test with key: {}", key_id);
    println!(
        "   📄 Test message: \"{}\"",
        String::from_utf8_lossy(&test_message)
    );
    println!("   📏 Message size: {} bytes", test_message.len());

    let num_signatures = 5;
    let mut durations = Vec::new();

    println!("\n   🔄 Generating {} signatures...", num_signatures);

    for i in 1..=num_signatures {
        let start = Instant::now();
        let signature = signer.sign(&test_message).await?;
        let duration = start.elapsed();

        durations.push(duration);

        println!("      #{}: {:?} ({} bytes)", i, duration, signature.len());
    }

    // Calculate statistics
    let total_time: std::time::Duration = durations.iter().sum();
    let avg_time = total_time / num_signatures as u32;
    let min_time = durations.iter().min().unwrap();
    let max_time = durations.iter().max().unwrap();

    println!("\n   📊 Performance Statistics:");
    println!("      ⏱️ Total time: {:?}", total_time);
    println!("      📈 Average: {:?}", avg_time);
    println!("      ⚡ Fastest: {:?}", min_time);
    println!("      🐌 Slowest: {:?}", max_time);
    println!(
        "      🎯 Throughput: {:.2} signatures/sec",
        num_signatures as f64 / total_time.as_secs_f64()
    );

    Ok(())
}

async fn cleanup_keys(
    storage: &VaultStorage,
    key_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    print_step(6, "Cleanup Keys");

    for key_id in key_ids {
        println!("🗑️ Deleting key: {}", key_id);
        storage.delete(key_id).await?;
        println!("   ✅ Key deleted");
    }

    println!("\n🧹 All {} keys cleaned up successfully!", key_ids.len());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_session_header();

    // Initialize storage
    let storage = create_storage().await?;

    // Generate multiple keys for testing
    let key_ids = generate_multiple_keys(&storage).await?;

    // Test key existence functionality
    test_key_existence(&storage, &key_ids).await?;

    // Run comprehensive signing tests
    comprehensive_signing_test(&storage, &key_ids).await?;

    // Performance testing with one key
    if let Some(key_id) = key_ids.first() {
        performance_test(&storage, key_id).await?;
    }

    // Cleanup all keys
    cleanup_keys(&storage, &key_ids).await?;

    // Final summary
    println!("\n🎉 Vault Signing Demo Completed!");
    println!("{}", "=".repeat(60));
    println!("✅ Generated {} ECDSA P-256 keys", key_ids.len());
    println!("✅ Tested key existence checking");
    println!("✅ Signed multiple data types successfully");
    println!("✅ Completed performance benchmarking");
    println!("✅ Cleaned up all test keys");

    println!("\n💡 Features Demonstrated:");
    println!("  • Multiple key generation and management");
    println!("  • Comprehensive data type signing (empty, text, binary, large)");
    println!("  • Key existence verification");
    println!("  • Performance measurement and statistics");
    println!("  • Proper cleanup and resource management");

    println!("\n🔐 Security Highlights:");
    println!("  • Private keys secured within Vault's encryption boundary");
    println!("  • ECDSA P-256 cryptographic strength");
    println!("  • Direct signing of pre-hashed data");
    println!("  • Audit trail through Vault's logging system");

    Ok(())
}
