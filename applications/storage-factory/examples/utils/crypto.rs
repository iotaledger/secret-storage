// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic utilities for IOTA transactions

use blake2::{Blake2b, Digest};
use iota_types::base_types::IotaAddress;
use std::error::Error;

type Blake2b256 = Blake2b<typenum::U32>;

/// Derive IOTA address from DER-encoded public key using IOTA's addressing scheme
pub fn derive_iota_address_from_der(der_bytes: &[u8]) -> Result<IotaAddress, Box<dyn Error>> {
    // Extract raw public key from DER format
    let raw_pubkey = extract_raw_public_key_from_der(der_bytes)?;

    // AWS KMS uses secp256r1 (P-256)
    // The raw public key should be 65 bytes: 0x04 + 32 bytes X + 32 bytes Y
    if raw_pubkey.len() != 65 || raw_pubkey[0] != 0x04 {
        return Err("Invalid public key format - expected uncompressed secp256r1".into());
    }

    // IOTA address derivation: hash [flag || compressed_pubkey] with Blake2b-256
    // For secp256r1, flag = 0x02
    let compressed_pubkey = compress_public_key(&raw_pubkey)?;

    let mut pubkey_with_flag = Vec::new();
    pubkey_with_flag.push(0x02); // secp256r1 flag
    pubkey_with_flag.extend_from_slice(&compressed_pubkey);

    // Hash with Blake2b-256 for IOTA address
    let hash = Blake2b256::digest(&pubkey_with_flag);

    // Create IOTA address from full hash (32 bytes)
    let mut address_array = [0u8; 32];
    address_array.copy_from_slice(&hash[..]);
    let address = IotaAddress::from_bytes(address_array)?;

    Ok(address)
}

/// Extract raw public key bytes from DER encoding
pub fn extract_raw_public_key_from_der(der_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // DER structure for secp256r1: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING }

    if der_bytes.len() < 70 {
        return Err("Invalid DER: too short".into());
    }

    // Look for the bit string tag (0x03) and extract the public key
    for i in 0..der_bytes.len().saturating_sub(65) {
        if der_bytes[i] == 0x03 && der_bytes.get(i + 1) == Some(&0x42) {
            // Found bit string with 66 bytes (0x42 = 66 decimal)
            // Next byte should be 0x00 (unused bits), then 65 bytes of public key
            if der_bytes.get(i + 2) == Some(&0x00) && i + 3 + 65 <= der_bytes.len() {
                return Ok(der_bytes[i + 3..i + 3 + 65].to_vec());
            }
        }
    }

    Err("Could not extract public key from DER - invalid format".into())
}

/// Compress secp256r1 public key from uncompressed (65 bytes) to compressed (33 bytes)
pub fn compress_public_key(uncompressed_pubkey: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if uncompressed_pubkey.len() != 65 || uncompressed_pubkey[0] != 0x04 {
        return Err("Invalid uncompressed public key format".into());
    }

    // Extract X and Y coordinates (32 bytes each)
    let x = &uncompressed_pubkey[1..33];
    let y = &uncompressed_pubkey[33..65];

    // Determine if Y is even or odd (for compression)
    let y_is_even = y[31] & 1 == 0;

    // Create compressed public key: [prefix][X coordinate]
    let mut compressed = Vec::new();
    compressed.push(if y_is_even { 0x02 } else { 0x03 }); // Compression prefix
    compressed.extend_from_slice(x); // X coordinate (32 bytes)

    Ok(compressed)
}

/// Parse DER signature into r and s components with canonicalization
#[allow(dead_code)]
pub fn parse_der_signature(der_signature: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    // Very basic DER parsing for ECDSA signatures
    // DER format: 30 [length] 02 [r_length] [r_bytes] 02 [s_length] [s_bytes]

    if der_signature.len() < 8 || der_signature[0] != 0x30 {
        return Err("Invalid DER signature format".into());
    }

    let mut pos = 2; // Skip 30 and total length

    // Parse r
    if der_signature[pos] != 0x02 {
        return Err("Expected INTEGER tag for r".into());
    }
    pos += 1;
    let r_len = der_signature[pos] as usize;
    pos += 1;
    let mut r_bytes = der_signature[pos..pos + r_len].to_vec();
    pos += r_len;

    // Remove leading zero if present (DER encoding requirement)
    if r_bytes.len() > 32 && r_bytes[0] == 0x00 {
        r_bytes = r_bytes[1..].to_vec();
    }

    // Pad to 32 bytes if needed
    while r_bytes.len() < 32 {
        r_bytes.insert(0, 0x00);
    }

    // Parse s
    if der_signature[pos] != 0x02 {
        return Err("Expected INTEGER tag for s".into());
    }
    pos += 1;
    let s_len = der_signature[pos] as usize;
    pos += 1;
    let mut s_bytes = der_signature[pos..pos + s_len].to_vec();

    // Remove leading zero if present
    if s_bytes.len() > 32 && s_bytes[0] == 0x00 {
        s_bytes = s_bytes[1..].to_vec();
    }

    // Pad to 32 bytes if needed
    while s_bytes.len() < 32 {
        s_bytes.insert(0, 0x00);
    }

    // Canonicalize s value (ensure it's low)
    s_bytes = canonicalize_s_value(&s_bytes)?;

    Ok((r_bytes, s_bytes))
}

/// Canonicalize ECDSA signature s value to ensure it's in the lower half
/// For secp256r1, if s > n/2, then s' = n - s
#[allow(dead_code)]
pub fn canonicalize_s_value(s_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // secp256r1 curve order: n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    let n_div_2: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31,
        0x92, 0xa8,
    ];

    // Convert s_bytes to comparison format
    let mut s_32 = [0u8; 32];
    let s_len = std::cmp::min(s_bytes.len(), 32);
    s_32[32 - s_len..].copy_from_slice(&s_bytes[s_bytes.len() - s_len..]);

    // Check if s > n/2 by comparing bytes
    let mut s_high = false;
    for i in 0..32 {
        if s_32[i] > n_div_2[i] {
            s_high = true;
            break;
        } else if s_32[i] < n_div_2[i] {
            break;
        }
    }

    if s_high {
        // Calculate n - s
        // n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        let n: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];

        let mut result = [0u8; 32];
        let mut borrow = 0u16;

        // Perform n - s (big-endian subtraction)
        for i in (0..32).rev() {
            let temp = n[i] as u16 + 256 - s_32[i] as u16 - borrow;
            result[i] = (temp % 256) as u8;
            borrow = if temp < 256 { 1 } else { 0 };
        }

        Ok(result.to_vec())
    } else {
        // s is already low, return as-is
        Ok(s_32.to_vec())
    }
}
