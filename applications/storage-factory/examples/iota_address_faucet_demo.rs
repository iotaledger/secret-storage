// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA Address Generation and Faucet Demo
//!
//! This demonstrates:
//! 1. Dynamic KMS key generation with timestamp alias
//! 2. Generate IOTA-compatible address using public key hash
//! 3. Automatically request testnet faucet funds
//!
//! Run with: AWS_REGION=eu-west-1 cargo run --package storage-factory --example iota_address_faucet_demo
//!
//! Prerequisites: Configure AWS credentials (one of the following):
//! - AWS CLI: `aws configure` 
//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
//! - AWS Profile: `export AWS_PROFILE=your-profile-name`

mod utils;

use secret_storage_core::{KeySign, Signer};
use std::error::Error;
use storage_factory::StorageBuilder;
use utils::{crypto::*, faucet::*, key_generation::*};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("🚀 IOTA Address Generation & Faucet Demo");
    println!("=========================================");

    // Initialize storage
    println!("🔧 Initializing AWS KMS storage...");
    let storage = StorageBuilder::new().aws_kms().build_aws_kms().await?;
    println!("✅ AWS KMS storage initialized");

    // Step 1: Generate dynamic KMS key
    println!("\n📋 STEP 1: Generating new KMS key with dynamic alias");
    println!("🔑 Generating new KMS key with dynamic alias...");
    let alias = generate_key_alias();
    println!("   Generated alias: {}", alias);
    let (key_id, public_key_der) = generate_dynamic_key(&storage, alias).await?;
    println!("✅ Key generated successfully");
    println!("   Key alias: {}", key_id);
    println!("   Public key size: {} bytes", public_key_der.len());
    println!(
        "   DER format (first 20 bytes): {}",
        hex::encode(&public_key_der[..20.min(public_key_der.len())])
    );

    // Step 2: Generate IOTA-compatible address
    println!("\n📋 STEP 2: Generating IOTA-compatible address");
    let iota_address = derive_iota_address_from_der(&public_key_der)?;
    println!("✅ IOTA-compatible address: {}", iota_address);

    // Step 3: Test signing capability (to verify key works)
    println!("\n📋 STEP 3: Testing KMS signing capability");
    let signer = storage.get_signer(&key_id)?;

    let test_message = b"IOTA testnet transaction".to_vec();
    let signature = signer.sign(&test_message).await?;
    println!(
        "✅ KMS signature test successful: {} bytes",
        signature.len()
    );

    // Step 4: Request testnet faucet
    println!("\n📋 STEP 4: Requesting testnet faucet funds");
    println!("Address: {}", iota_address);
    println!("   Sending faucet request...");

    match request_faucet_funds(iota_address).await {
        Ok(response) => {
            println!("✅ Faucet request successful!");
            println!("   Response: {}", response);
        }
        Err(e) => {
            println!("⚠️  Faucet request failed: {}", e);
            println!("   You can manually request funds at: https://faucet.testnet.iota.cafe");
            println!("   Address to fund: {}", iota_address);
        }
    }

    // Summary
    println!("\n🎉 Demo completed successfully!");
    println!("Summary:");
    println!("  - KMS key alias: {}", key_id);
    println!("  - Public key size: {} bytes", public_key_der.len());
    println!("  - Generated IOTA address: {}", iota_address);
    println!("  - Faucet request: Attempted");
    println!("\n💡 Next steps:");
    println!("  - Wait for faucet funds to arrive (1-2 minutes)");
    println!(
        "  - Check balance at: https://explorer.iota.org/address/{}?network=testnet",
        iota_address
    );
    println!("  - Use this address for IOTA transactions with KMS signing");

    Ok(())
}
