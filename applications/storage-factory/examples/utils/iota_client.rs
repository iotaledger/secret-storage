// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! IOTA client utilities

use crate::utils::crypto::{
    canonicalize_s_value, compress_public_key, extract_raw_public_key_from_der, parse_der_signature,
};
use iota_json_rpc_types::IotaTransactionBlockResponseOptions;
use iota_sdk::IotaClient;
use iota_types::base_types::IotaAddress;
use iota_types::{
    crypto::{Signature, ToFromBytes},
    signature::GenericSignature,
    transaction::{Transaction, TransactionData},
};
use std::error::Error;

pub fn to_iota_signature(
    signature: &[u8],
    public_key_der: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Extract raw public key to determine signature type
    let raw_pubkey = extract_raw_public_key_from_der(public_key_der)?;

    let mut sig_bytes = Vec::new();

    if raw_pubkey.len() == 65 && raw_pubkey[0] == 0x04 {
        // ECDSA secp256r1 case
        println!("🔍 Processing ECDSA secp256r1 signature");

        // Parse DER signature
        let (r_bytes, s_bytes) = parse_der_signature(signature)?;

        // Canonicalize s value for IOTA compliance
        let s_canonical = canonicalize_s_value(&s_bytes)?;

        // Compress public key
        let compressed_pubkey = compress_public_key(&raw_pubkey)?;

        // Create IOTA signature format: [scheme_flag:1][r:32][s:32][pubkey_compressed:33]
        sig_bytes.push(0x02); // secp256r1 scheme flag

        // Ensure r and s are exactly 32 bytes
        let mut r_32 = [0u8; 32];
        let mut s_32 = [0u8; 32];
        let r_len = std::cmp::min(r_bytes.len(), 32);
        let s_len = std::cmp::min(s_canonical.len(), 32);
        r_32[32 - r_len..].copy_from_slice(&r_bytes[r_bytes.len() - r_len..]);
        s_32[32 - s_len..].copy_from_slice(&s_canonical[s_canonical.len() - s_len..]);

        sig_bytes.extend_from_slice(&r_32);
        sig_bytes.extend_from_slice(&s_32);
        sig_bytes.extend_from_slice(&compressed_pubkey);
    } else {
        return Err(format!(
            "Unsupported public key format: {} bytes. Only ECDSA secp256r1 (65 bytes uncompressed) is supported",
            raw_pubkey.len()
        ).into());
    }

    Ok(sig_bytes)
}

/// Submit signed transaction via IOTA SDK (recommended)
pub async fn submit_via_sdk(
    iota_client: &IotaClient,
    transaction_data: &TransactionData,
    signature: &[u8],
    public_key_der: &[u8],
) -> Result<String, Box<dyn Error>> {
    // // Extract raw public key to determine signature type
    // let raw_pubkey = extract_raw_public_key_from_der(public_key_der)?;

    // let mut sig_bytes = Vec::new();

    // if raw_pubkey.len() == 65 && raw_pubkey[0] == 0x04 {
    //     // ECDSA secp256r1 case
    //     println!("🔍 Processing ECDSA secp256r1 signature");

    //     // Parse DER signature
    //     let (r_bytes, s_bytes) = parse_der_signature(signature)?;

    //     // Canonicalize s value for IOTA compliance
    //     let s_canonical = canonicalize_s_value(&s_bytes)?;

    //     // Compress public key
    //     let compressed_pubkey = compress_public_key(&raw_pubkey)?;

    //     // Create IOTA signature format: [scheme_flag:1][r:32][s:32][pubkey_compressed:33]
    //     sig_bytes.push(0x02); // secp256r1 scheme flag

    //     // Ensure r and s are exactly 32 bytes
    //     let mut r_32 = [0u8; 32];
    //     let mut s_32 = [0u8; 32];
    //     let r_len = std::cmp::min(r_bytes.len(), 32);
    //     let s_len = std::cmp::min(s_canonical.len(), 32);
    //     r_32[32 - r_len..].copy_from_slice(&r_bytes[r_bytes.len() - r_len..]);
    //     s_32[32 - s_len..].copy_from_slice(&s_canonical[s_canonical.len() - s_len..]);

    //     sig_bytes.extend_from_slice(&r_32);
    //     sig_bytes.extend_from_slice(&s_32);
    //     sig_bytes.extend_from_slice(&compressed_pubkey);
    // } else {
    //     return Err(format!(
    //         "Unsupported public key format: {} bytes. Only ECDSA secp256r1 (65 bytes uncompressed) is supported",
    //         raw_pubkey.len()
    //     ).into());
    // }
    let sig_bytes = to_iota_signature(signature, public_key_der)?;

    // ECDSA secp256r1 signature format:
    // [0x02][r:32][s:32][pubkey_compressed:33] = 98 bytes

    // Create GenericSignature from signature bytes
    // For ECDSA secp256r1, we use the signature format directly
    let signature = Signature::from_bytes(&sig_bytes)
        .map_err(|e| format!("Failed to create signature: {}", e))?;
    let user_sig = GenericSignature::from(signature);

    // Create signed transaction using from_generic_sig_data
    let signed_tx = Transaction::from_generic_sig_data(transaction_data.clone(), vec![user_sig]);

    // Submit transaction via quorum driver API
    let response = iota_client
        .quorum_driver_api()
        .execute_transaction_block(
            signed_tx,
            IotaTransactionBlockResponseOptions::default(),
            iota_types::quorum_driver_types::ExecuteTransactionRequestType::WaitForLocalExecution,
        )
        .await
        .map_err(|e| format!("Failed to submit transaction: {}", e))?;

    Ok(response.digest.to_string())
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
