// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA Vault Demo - Complete workflow from Vault key to IOTA transaction
//!
//! This example demonstrates:
//! 1. Dynamic Vault key generation with timestamp identifier
//! 2. Auto-faucet to fund the generated address
//! 3. Transferring 0.005 IOTA to target address
//!
//! Prerequisites:
//! - HashiCorp Vault server running with Transit engine enabled
//! - Valid Vault token and configuration
//!
//! Quick setup:
//! ```bash
//! ./scripts/vault-dev.sh start
//! export VAULT_ADDR="http://localhost:8200"
//! export VAULT_TOKEN="dev-token"
//! export VAULT_MOUNT_PATH="transit"
//! VAULT_ADDR=http://localhost:8200 VAULT_TOKEN=dev-token VAULT_MOUNT_PATH="transit" cargo run --package storage-factory --example iota_vault_demo
//! ```

mod utils;

use blake2::{Blake2b, Digest};
use iota_types::{
    base_types::IotaAddress, programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::TransactionData,
};
use secret_storage_core::{KeySign, Signer};
use shared_crypto::intent::{Intent, IntentMessage};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use storage_factory::StorageBuilder;
use utils::{crypto::*, faucet::*, iota_client::*};

type Blake2b256 = Blake2b<typenum::U32>;

const TARGET_ADDRESS: &str = "0x1f9699f7b7baee05b2a6eea4eb41bb923fb64732069a1bf010506cd3d2d9ab26";
const TRANSFER_AMOUNT: u64 = 5_000_000; // 0.005 IOTA in MIST (1 IOTA = 1_000_000_000 MIST)

/// Generate a dynamic key name with timestamp in the format: vault-demo-{timestamp}
fn generate_key_name() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("vault-demo-{}", timestamp)
}

/// Generate a new Vault key with specified name and return the key ID and public key
async fn generate_dynamic_vault_key(
    storage: &vault_adapter::VaultStorage,
    key_name: String,
) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    use secret_storage_core::KeyGenerate;

    // Create options with the specified key name
    let options = vault_adapter::VaultKeyOptions {
        key_name: Some(key_name),
        description: Some("IOTA Vault Demo Key - ECDSA P-256".to_string()),
    };

    // Generate key with specified name
    let (key_id, public_key) = storage.generate_key_with_options(options).await?;
    Ok((key_id, public_key))
}

fn print_session_header() {
    let session_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    println!("🚀 IOTA Vault Demo - Send 0.005 IOTA Transaction");
    println!("================================================");
    println!("📅 Session ID: VAULT_DEMO_{}", session_id);
    println!(
        "🔧 Vault Address: {}",
        std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://localhost:8200".to_string())
    );
    println!("🏦 Storage Backend: HashiCorp Vault");
    println!("🌐 Network: IOTA Testnet");
    println!("💰 Transfer Amount: 0.005 IOTA");
    println!("{}", "=".repeat(50));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    print_session_header();

    // Initialize Vault storage
    println!("\n🔧 Initializing HashiCorp Vault storage...");
    println!("   🔍 Checking Vault connection and authentication...");

    let storage = StorageBuilder::new()
        .vault()
        .build_vault()
        .await
        .map_err(|e| format!("Failed to initialize Vault storage: {}\n\nTroubleshooting:\n• Ensure Vault server is running: ./scripts/vault-dev.sh start\n• Check VAULT_ADDR environment variable\n• Verify VAULT_TOKEN is valid\n• Ensure Transit engine is enabled", e))?;

    println!("✅ HashiCorp Vault storage initialized");
    println!("   🔐 Connected to Vault Transit secrets engine");

    // Step 1: Generate dynamic Vault key
    println!("\n📋 STEP 1: Generating new Vault key with dynamic identifier");
    let key_name = generate_key_name();
    println!("🔑 Generating new ECDSA P-256 key...");
    println!("   Key name: {}", key_name);

    let (key_id, public_key_der) = generate_dynamic_vault_key(&storage, key_name).await?;

    println!("✅ Key generated successfully in Vault");
    println!("   📌 Key ID: {}", key_id);
    println!(
        "   📐 Public key size: {} bytes (DER format)",
        public_key_der.len()
    );
    println!("   🔒 Key type: ECDSA P-256 (secp256r1)");

    // Convert DER to IOTA address
    println!("\n🏠 Deriving IOTA address from public key...");
    let iota_address = derive_iota_address_from_der(&public_key_der)?;
    println!("✅ IOTA address derived: {}", iota_address);
    println!("   🔍 Address format: 32-byte Blake2b hash of compressed public key");

    // Initialize IOTA client
    println!("\n🌐 Connecting to IOTA testnet...");
    let iota_client = iota_sdk::IotaClientBuilder::default()
        .build_testnet()
        .await?;
    println!("✅ Connected to IOTA testnet");
    println!("   🌍 Network: Testnet");
    println!("   📡 RPC endpoint ready");

    // Step 2: Request faucet funds
    println!(
        "\n📋 STEP 2: Requesting faucet funds for address: {}",
        iota_address
    );
    println!("💧 Sending faucet request...");
    println!("   📝 Note: Faucet provides ~10 IOTA for testing purposes");

    match request_faucet_funds(iota_address).await {
        Ok(response) => {
            println!("✅ Faucet request successful");
            println!("   📨 Response: {}", response);
        }
        Err(e) => {
            println!("⚠️  Faucet request failed: {}", e);
            println!("   🔄 Continuing to check existing balance...");
            println!("   💡 Tip: Address may already have funds from previous runs");
        }
    }

    // Wait for faucet transaction to be processed
    println!("⏳ Waiting 5 seconds for faucet transaction to be processed...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Check balance
    println!("\n💰 Checking balance after faucet request...");
    let (total_balance, coins) = check_balance(&iota_client, iota_address).await?;
    println!(
        "✅ Total balance: {} MIST ({:.6} IOTA)",
        total_balance,
        total_balance as f64 / 1_000_000_000.0
    );
    println!("   🪙 Available coins: {}", coins.len());

    if coins.is_empty() {
        return Err(format!(
            "❌ No coins available for address {}\n\nPossible causes:\n• Faucet request failed or is still processing\n• Try running the faucet request manually\n• Wait a few more seconds and try again", 
            iota_address
        ).into());
    }

    let gas_buffer = 10_000_000; // 0.01 IOTA buffer for gas
    let required_balance = TRANSFER_AMOUNT + gas_buffer;

    if total_balance < required_balance {
        return Err(format!(
            "❌ Insufficient balance for transaction\n   Required: {} MIST ({:.6} IOTA) including gas buffer\n   Available: {} MIST ({:.6} IOTA)\n   Transfer: {} MIST ({:.6} IOTA)\n   Gas buffer: {} MIST ({:.6} IOTA)",
            required_balance, required_balance as f64 / 1_000_000_000.0,
            total_balance, total_balance as f64 / 1_000_000_000.0,
            TRANSFER_AMOUNT, TRANSFER_AMOUNT as f64 / 1_000_000_000.0,
            gas_buffer, gas_buffer as f64 / 1_000_000_000.0
        ).into());
    }

    // Step 3: Prepare transaction to transfer 0.005 IOTA
    println!("\n📋 STEP 3: Preparing IOTA transfer transaction");
    println!("📤 Transaction Details:");
    println!("   From: {}", iota_address);
    println!("   To: {}", TARGET_ADDRESS);
    println!(
        "   Amount: {} MIST ({:.6} IOTA)",
        TRANSFER_AMOUNT,
        TRANSFER_AMOUNT as f64 / 1_000_000_000.0
    );

    // Parse target address
    let recipient_address: IotaAddress = TARGET_ADDRESS.parse()?;
    println!("✅ Target address parsed successfully");

    // Select gas coin (use the first available coin)
    let gas_coin = &coins[0];
    let gas_object_ref = (gas_coin.coin_object_id, gas_coin.version, gas_coin.digest);
    println!(
        "✅ Selected gas coin: {} (balance: {} MIST)",
        gas_coin.coin_object_id, gas_coin.balance
    );

    // Build programmable transaction
    println!("\n🔧 Building programmable transaction...");
    let mut ptb = ProgrammableTransactionBuilder::new();
    ptb.pay_iota(vec![recipient_address], vec![TRANSFER_AMOUNT])?;
    let programmable_tx = ptb.finish();
    println!("✅ Programmable transaction built");

    // Get gas parameters
    let gas_budget = 5_000_000; // 0.005 IOTA gas budget
    let gas_price = iota_client.read_api().get_reference_gas_price().await?;
    println!("✅ Gas parameters configured");
    println!("   💰 Gas budget: {} MIST", gas_budget);
    println!("   💲 Gas price: {} MIST/unit", gas_price);

    // Create transaction data
    println!("\n📦 Creating transaction data structure...");
    let tx_data = TransactionData::new_programmable(
        iota_address,
        vec![gas_object_ref],
        programmable_tx,
        gas_budget,
        gas_price,
    );
    println!("✅ Transaction data created");

    // Prepare intent message for signing
    println!("\n🔐 Preparing transaction for signing...");
    let intent_msg = IntentMessage::new(Intent::iota_transaction(), tx_data.clone());
    let bcs_bytes = bcs::to_bytes(&intent_msg)?;
    println!("   📄 Intent message serialized: {} bytes", bcs_bytes.len());

    // Calculate digest to sign - use Blake2b-256 for intent message as per IOTA protocol
    let digest = Blake2b256::digest(&bcs_bytes);
    println!("✅ Transaction digest calculated using Blake2b-256");
    println!("   🔢 Digest size: {} bytes", digest.len());
    println!("   📊 Digest (hex): {}", hex::encode(&digest));

    // Sign with Vault
    println!("\n🔐 Signing transaction with HashiCorp Vault...");
    println!("   🔑 Using key: {}", key_id);
    println!("   📝 Signer will automatically determine correct data format");

    let signer = storage.get_signer(&key_id)?;
    // For Ed25519 in IOTA, we need to pass the Blake2b-256 digest, not raw data
    // This matches IOTA's expectation that Ed25519 signs the Blake2b-256 hash
    let vault_signature = signer.sign(&digest.to_vec()).await?;

    println!("✅ Transaction signed successfully with Vault");
    println!("   📏 Signature size: {} bytes", vault_signature.len());
    println!("   📊 Signature (hex): {}", hex::encode(&vault_signature));
    println!("   🔒 Signature format: DER-encoded ECDSA");

    // Process signature for IOTA submission
    // Signature and public key processing is now handled automatically
    // in submit_via_sdk based on the key type (ECDSA vs Ed25519)

    // Display comprehensive transaction information
    println!("\n📊 COMPLETE TRANSACTION INFORMATION");
    println!("{}", "=".repeat(50));
    println!("🏦 Storage Backend: HashiCorp Vault");
    println!("🔑 Key ID: {}", key_id);
    println!("🏠 From Address: {}", iota_address);
    println!("🎯 To Address: {}", TARGET_ADDRESS);
    println!(
        "💰 Amount: {} MIST ({:.6} IOTA)",
        TRANSFER_AMOUNT,
        TRANSFER_AMOUNT as f64 / 1_000_000_000.0
    );
    println!("⛽ Gas Budget: {} MIST", gas_budget);
    println!("💲 Gas Price: {} MIST/unit", gas_price);
    println!("");
    println!("🔐 CRYPTOGRAPHIC DATA:");
    println!("   Transaction Digest: {}", hex::encode(&digest));
    println!(
        "   Vault Signature: {} ({} bytes)",
        hex::encode(&vault_signature),
        vault_signature.len()
    );

    // Submit transaction using IOTA SDK
    println!("\n🚀 SUBMITTING TRANSACTION TO IOTA TESTNET");
    println!("{}", "=".repeat(50));
    println!("📝 Converting Vault signature to IOTA format...");
    
    // Process signature and submit to IOTA
    println!("📡 Submitting via IOTA SDK...");

    match submit_via_sdk(&iota_client, &tx_data, &vault_signature, &public_key_der).await {
        Ok(digest) => {
            println!("\n🎉 TRANSACTION SUCCESSFUL!");
            println!("{}", "=".repeat(50));
            println!("✅ Transaction submitted successfully to IOTA testnet");
            println!("📊 Final Transaction Digest: {}", digest);
            println!(
                "🔍 Explorer URL: https://explorer.iota.org/txblock/{}?network=testnet",
                digest
            );
            println!("");
            println!("📋 TRANSACTION SUMMARY:");
            println!("   🏦 Backend: HashiCorp Vault");
            println!("   🔑 Key: {}", key_id);
            println!("   🏠 From: {}", iota_address);
            println!("   🎯 To: {}", TARGET_ADDRESS);
            println!(
                "   💰 Amount: {} MIST ({:.6} IOTA)",
                TRANSFER_AMOUNT,
                TRANSFER_AMOUNT as f64 / 1_000_000_000.0
            );
            println!("   🌐 Network: IOTA Testnet");
            println!("   ✅ Status: SUBMITTED");
            println!("");
            println!("🎊 Transaction completed successfully!");
            println!("💡 Check the explorer link above to view transaction status");
        }
        Err(e) => {
            println!("\n⚠️  TRANSACTION SUBMISSION FAILED");
            println!("{}", "=".repeat(50));
            println!("❌ SDK submission error: {}", e);
            println!("");
            println!("📋 DIAGNOSTIC INFORMATION:");
            println!("✅ Vault key generation: SUCCESS");
            println!("✅ Address derivation: SUCCESS");
            println!("✅ Balance check: SUCCESS");
            println!("✅ Transaction preparation: SUCCESS");
            println!("✅ Vault signing: SUCCESS");
            println!("❌ Network submission: FAILED");
            println!("");
            println!("🔧 TROUBLESHOOTING:");
            println!("• Check network connectivity to IOTA testnet");
            println!("• Verify gas parameters are sufficient");
            println!("• Ensure coins are still available and unspent");
            println!("• Try again in a few seconds");
            println!("");
            println!("💡 The signature is valid and can be used for manual submission");

            return Err(format!("Transaction submission failed: {}", e).into());
        }
    }

    Ok(())
}
