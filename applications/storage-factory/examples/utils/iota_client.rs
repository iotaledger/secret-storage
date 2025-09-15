// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA client utilities

use crate::utils::crypto::{
    compress_public_key, extract_raw_public_key_from_der, parse_der_signature,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use iota_types::base_types::IotaAddress;
use std::error::Error;
use std::process::Command;
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

/// Submit signed transaction via IOTA CLI
#[allow(dead_code)]
pub async fn submit_via_iota_cli(
    transaction_bytes: &[u8],
    der_signature: &[u8],
    public_key_der: &[u8],
) -> Result<String, Box<dyn Error>> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let temp_dir = format!("/tmp/iota_kms_{}", timestamp);

    // Create temporary directory
    fs::create_dir_all(&temp_dir)?;

    // Write transaction bytes to file (Base64 format)
    let tx_file = format!("{}/tx_bytes.txt", temp_dir);
    fs::write(&tx_file, BASE64.encode(transaction_bytes))?;

    // Convert DER signature to required format and write to file
    let (r_bytes, s_bytes) = parse_der_signature(der_signature)?;
    let raw_pubkey = extract_raw_public_key_from_der(public_key_der)?;
    let compressed_pubkey = compress_public_key(&raw_pubkey)?;

    // Create IOTA signature format: [scheme_flag:1][r:32][s:32][pubkey_compressed:33]
    let mut sig_bytes = Vec::new();
    sig_bytes.push(0x02); // secp256r1 scheme (0x02 according to IOTA scheme flags)

    // Ensure r and s are exactly 32 bytes
    let mut r_32 = [0u8; 32];
    let mut s_32 = [0u8; 32];
    let r_len = std::cmp::min(r_bytes.len(), 32);
    let s_len = std::cmp::min(s_bytes.len(), 32);
    r_32[32 - r_len..].copy_from_slice(&r_bytes[r_bytes.len() - r_len..]);
    s_32[32 - s_len..].copy_from_slice(&s_bytes[s_bytes.len() - s_len..]);

    sig_bytes.extend_from_slice(&r_32);
    sig_bytes.extend_from_slice(&s_32);
    sig_bytes.extend_from_slice(&compressed_pubkey);

    let sig_file = format!("{}/signature.txt", temp_dir);
    fs::write(&sig_file, BASE64.encode(&sig_bytes))?;

    // Read the Base64 content from files
    let tx_b64 = fs::read_to_string(&tx_file)?;
    let sig_b64 = fs::read_to_string(&sig_file)?;

    // Execute IOTA CLI command with Base64 strings directly

    let output = Command::new("iota")
        .args([
            "client",
            "execute-signed-tx",
            "--tx-bytes",
            tx_b64.trim(),
            "--signatures",
            sig_b64.trim(),
        ])
        .output();

    // Clean up temporary files
    let _ = fs::remove_dir_all(&temp_dir);

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let stderr = String::from_utf8_lossy(&result.stderr);

            if result.status.success() {
                // Parse transaction digest from output
                for line in stdout.lines() {
                    if line.contains("Transaction Digest:") || line.contains("digest:") {
                        if let Some(digest) = line.split_whitespace().last() {
                            return Ok(digest.to_string());
                        }
                    }
                }
                Ok("Transaction submitted successfully (digest not found in output)".to_string())
            } else {
                Err(format!("IOTA CLI failed: {}\nstderr: {}", stdout, stderr).into())
            }
        }
        Err(e) => Err(format!(
            "Failed to execute IOTA CLI: {}. Make sure 'iota' CLI is installed and in PATH.",
            e
        )
        .into()),
    }
}

/// Check balance for an IOTA address
#[allow(dead_code)]
pub async fn check_balance(
    iota_client: &iota_sdk::IotaClient,
    address: IotaAddress,
) -> Result<(u64, Vec<iota_json_rpc_types::Coin>), Box<dyn Error>> {
    let coins = iota_client
        .coin_read_api()
        .get_coins(address, None, None, None)
        .await?;

    let total_balance: u64 = coins.data.iter().map(|coin| coin.balance).sum();
    Ok((total_balance, coins.data))
}

/// Print manual CLI instructions for transaction submission
#[allow(dead_code)]
pub fn print_manual_cli_instructions(
    transaction_bytes: &[u8],
    kms_signature: &[u8],
    public_key_der: &[u8],
) -> Result<(), Box<dyn Error>> {
    println!("\n💡 Alternative: Use IOTA CLI manually with the data above:");
    println!("1. Save transaction data to file (Base64 format):");
    println!(
        "   echo '{}' > tx_data.txt",
        BASE64.encode(transaction_bytes)
    );
    println!("2. Save signature components (Base64 format):");

    let (r_bytes, s_bytes) = parse_der_signature(kms_signature)?;
    let raw_pubkey = extract_raw_public_key_from_der(public_key_der)?;
    let compressed_pubkey = compress_public_key(&raw_pubkey)?;
    let mut sig_bytes = Vec::new();
    sig_bytes.push(0x02); // secp256r1 scheme flag
    let mut r_32 = [0u8; 32];
    let mut s_32 = [0u8; 32];
    let r_len = std::cmp::min(r_bytes.len(), 32);
    let s_len = std::cmp::min(s_bytes.len(), 32);
    r_32[32 - r_len..].copy_from_slice(&r_bytes[r_bytes.len() - r_len..]);
    s_32[32 - s_len..].copy_from_slice(&s_bytes[s_bytes.len() - s_len..]);
    sig_bytes.extend_from_slice(&r_32);
    sig_bytes.extend_from_slice(&s_32);
    sig_bytes.extend_from_slice(&compressed_pubkey);
    println!("   echo '{}' > signature.txt", BASE64.encode(&sig_bytes));
    println!("3. Submit transaction:");
    println!("   iota client execute-signed-tx --tx-bytes tx_data.txt --signatures signature.txt");

    Ok(())
}
