// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA KMS Demo - Complete workflow from KMS key to IOTA transaction
//!
//! This example demonstrates:
//! 1. Dynamic KMS key generation with timestamp alias
//! 2. Auto-faucet to fund the generated address
//! 3. Transferring 0.005 IOTA to target address
//!
//! Run with: AWS_REGION=eu-west-1 cargo run --package storage-factory --example iota_kms_demo
//!
//! Prerequisites: Configure AWS credentials (one of the following):
//! - AWS CLI: `aws configure`
//! - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
//! - AWS Profile: `export AWS_PROFILE=your-profile-name`

mod utils;

use blake2::{Blake2b, Digest};
use iota_types::{
    base_types::IotaAddress, programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::TransactionData,
};
use secret_storage_core::{KeySign, Signer};
use shared_crypto::intent::{Intent, IntentMessage};
use std::error::Error;
use storage_factory::StorageBuilder;
use utils::{crypto::*, faucet::*, iota_client::*, key_generation::*};

type Blake2b256 = Blake2b<typenum::U32>;

const TARGET_ADDRESS: &str = "0x1f9699f7b7baee05b2a6eea4eb41bb923fb64732069a1bf010506cd3d2d9ab26";
const TRANSFER_AMOUNT: u64 = 50_000_000; // 0.05 IOTA in MIST (1 IOTA = 1_000_000_000 MIST)

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("🚀 IOTA KMS Demo - Send 0.005 IOTA Transaction");
    println!("===============================================");

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

    // Convert DER to IOTA address
    let iota_address = derive_iota_address_from_der(&public_key_der)?;
    println!("✅ IOTA address derived: {}", iota_address);

    // Initialize IOTA client
    println!("\n🌐 Connecting to IOTA testnet...");
    let iota_client = iota_sdk::IotaClientBuilder::default()
        .build_testnet()
        .await?;
    println!("✅ Connected to IOTA testnet");

    // Step 2: Request faucet funds
    println!(
        "\n📋 STEP 2: Requesting faucet funds for address: {}",
        iota_address
    );
    println!("   Sending faucet request...");
    match request_faucet_funds(iota_address).await {
        Ok(response) => println!("✅ {}", response),
        Err(e) => println!(
            "⚠️  Faucet request failed: {}. Continuing to check balance...",
            e
        ),
    }

    // Wait a bit for faucet transaction to be processed
    println!("⏳ Waiting 5 seconds for faucet transaction to be processed...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Check balance
    println!("\n💰 Checking balance after faucet request...");
    let (total_balance, coins) = check_balance(&iota_client, iota_address).await?;
    println!(
        "✅ Total balance: {} MIST ({} IOTA)",
        total_balance,
        total_balance as f64 / 1_000_000_000.0
    );

    if coins.is_empty() {
        return Err(
            "❌ No coins available. Faucet request may have failed or is still processing.".into(),
        );
    }

    if total_balance < TRANSFER_AMOUNT + 5_000_000 {
        // Add buffer for gas
        return Err(format!(
            "❌ Insufficient balance. Need {} MIST + gas, have {} MIST",
            TRANSFER_AMOUNT, total_balance
        )
        .into());
    }

    // Step 3: Prepare transaction to transfer 0.005 IOTA
    println!("\n📋 STEP 3: Preparing to transfer 0.005 IOTA");
    println!("From: {}", iota_address);
    println!("To: {}", TARGET_ADDRESS);
    println!("Amount: {} MIST (0.005 IOTA)", TRANSFER_AMOUNT);

    // Parse target address
    let recipient_address: IotaAddress = TARGET_ADDRESS.parse()?;

    // Select gas coin (use the first available coin)
    let gas_coin = &coins[0];
    let gas_object_ref = (gas_coin.coin_object_id, gas_coin.version, gas_coin.digest);
    println!(
        "✅ Selected gas coin: {} (balance: {} MIST)",
        gas_coin.coin_object_id, gas_coin.balance
    );

    // Build programmable transaction
    let mut ptb = ProgrammableTransactionBuilder::new();
    ptb.pay_iota(vec![recipient_address], vec![TRANSFER_AMOUNT])?;
    let programmable_tx = ptb.finish();

    // Get gas parameters
    let gas_budget = 5_000_000;
    let gas_price = iota_client.read_api().get_reference_gas_price().await?;
    println!("✅ Gas budget: {}, Gas price: {}", gas_budget, gas_price);

    // Create transaction data
    let tx_data = TransactionData::new_programmable(
        iota_address,
        vec![gas_object_ref],
        programmable_tx,
        gas_budget,
        gas_price,
    );

    // Prepare intent message for signing
    let intent_msg = IntentMessage::new(Intent::iota_transaction(), tx_data.clone());
    let bcs_bytes = bcs::to_bytes(&intent_msg)?;

    // Calculate digest to sign - use Blake2b-256 for intent message as per IOTA docs
    // Then ECDSA will internally use SHA-256
    let digest = Blake2b256::digest(&bcs_bytes);
    println!("✅ Transaction digest prepared: {} bytes", digest.len());
    println!(
        "📊 Transaction Digest (Blake2b-256): {}",
        hex::encode(digest)
    );

    // Sign with KMS
    println!("\n🔐 Signing transaction with KMS...");
    let signer = storage.get_signer(&key_id)?;
    let kms_signature = signer.sign(&digest.to_vec()).await?;
    println!(
        "✅ Transaction signed with KMS: {} bytes",
        kms_signature.len()
    );
    println!("📊 KMS Signature (DER): {}", hex::encode(&kms_signature));

    // Convert DER signature components for IOTA submission
    println!("\n📦 Converting DER signature for IOTA submission...");
    let (r_bytes, s_bytes) = parse_der_signature(&kms_signature)?;
    println!(
        "✅ DER signature parsed: r={} bytes, s={} bytes",
        r_bytes.len(),
        s_bytes.len()
    );

    // Prepare final transaction data for submission
    let tx_hash = Blake2b256::digest(&bcs_bytes);
    let _tx_digest_hex = hex::encode(tx_hash);

    println!("\n🚀 Transaction ready for submission to IOTA testnet!");
    println!("📊 Transaction Details:");
    println!("  - From: {}", iota_address);
    println!("  - To: {}", TARGET_ADDRESS);
    println!("  - Amount: {} MIST (0.005 IOTA)", TRANSFER_AMOUNT);
    println!("  - Gas Budget: {} MIST", gas_budget);
    println!("  - Gas Price: {} MIST", gas_price);

    println!("\n📋 Signature Data (for IOTA CLI/SDK submission):");
    println!("  - Transaction Digest: {}", hex::encode(digest));
    println!("  - KMS Signature (DER): {}", hex::encode(&kms_signature));
    println!("  - R Component: {}", hex::encode(&r_bytes));
    println!("  - S Component: {}", hex::encode(&s_bytes));
    println!(
        "  - Public Key (Raw): {}",
        hex::encode(&extract_raw_public_key_from_der(&public_key_der)?)
    );
    let raw_key = extract_raw_public_key_from_der(&public_key_der)?;
    let compressed_key = compress_public_key(&raw_key)?;
    println!(
        "  - Public Key (Compressed): {}",
        hex::encode(&compressed_key)
    );

    println!("\n🎉 Transaction successfully prepared and signed with KMS!");

    // Submit transaction using IOTA SDK (recommended method)
    println!("\n🚀 Submitting transaction via IOTA SDK...");
    println!("📝 Converting signature to IOTA format and submitting transaction...");
    
    match submit_via_sdk(&iota_client, &tx_data, &kms_signature, &public_key_der).await {
        Ok(digest) => {
            println!("✅ Transaction submitted successfully via IOTA SDK!");
            println!("📊 Final Transaction Digest: {}", digest);
            println!(
                "🔍 View on IOTA Explorer: https://explorer.iota.org/txblock/{}?network=testnet",
                digest
            );

            println!("\n🎉 Transaction completed successfully!");
            println!("Summary:");
            println!("  - From: {}", iota_address);
            println!("  - To: {}", TARGET_ADDRESS);
            println!("  - Amount: {} MIST (0.005 IOTA)", TRANSFER_AMOUNT);
            println!("  - Network: IOTA Testnet");
            println!("  - Status: SUBMITTED");
        }
        Err(e) => {
            println!("⚠️  SDK submission failed: {}", e);
            println!("Transaction signing was successful, but submission failed.");
            println!("You can manually submit this transaction if needed.");
        }
    }

    Ok(())
}
