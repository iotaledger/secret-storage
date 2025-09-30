// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use base64::Engine;
use crate::{VaultError, utils::vault_client::VaultClient};

/// Create a new signing key in Vault's Transit engine
pub async fn create_signing_key(
    client: &VaultClient,
    key_name: &str,
    description: Option<&str>,
) -> Result<(), VaultError> {
    let path = format!("{}/keys/{}", client.config().mount_path, key_name);
    
    let mut payload = json!({
        "type": "ecdsa-p256",
        "exportable": false,
        "allow_plaintext_backup": false,
        "deletion_allowed": true
    });

    if let Some(desc) = description {
        payload["description"] = json!(desc);
    }

    client.post(&path, &payload).await?;
    Ok(())
}

/// Get public key from Vault
pub async fn get_public_key(
    client: &VaultClient,
    key_name: &str,
) -> Result<Vec<u8>, VaultError> {
    let path = format!("{}/keys/{}", client.config().mount_path, key_name);
    
    let response = client.get(&path).await?;
    
    let keys = response
        .get("data")
        .and_then(|d| d.get("keys"))
        .ok_or_else(|| VaultError::Api("No keys found in response".to_string()))?;

    // Get the latest version's public key
    let latest_version = keys
        .as_object()
        .ok_or_else(|| VaultError::Api("Keys is not an object".to_string()))?
        .keys()
        .filter_map(|k| k.parse::<u32>().ok())
        .max()
        .ok_or_else(|| VaultError::Api("No key versions found".to_string()))?;

    let public_key_data = keys
        .get(&latest_version.to_string())
        .and_then(|v| v.get("public_key"))
        .and_then(|pk| pk.as_str())
        .ok_or_else(|| VaultError::Api("Public key not found".to_string()))?;

    // Check if this looks like PEM (starts with -----BEGIN) or raw base64
    if public_key_data.starts_with("-----BEGIN") {
        // ECDSA case: Convert PEM to DER format
        let public_key_der = pem_to_der(public_key_data)?;
        Ok(public_key_der)
    } else {
        // Ed25519 case: Raw base64, decode directly
        let public_key_raw = base64::engine::general_purpose::STANDARD.decode(public_key_data)
            .map_err(VaultError::Base64)?;
        
        // For Ed25519, we need to create proper DER encoding
        // Ed25519 DER format: SEQUENCE { SEQUENCE { OID }, BIT STRING }
        create_ed25519_der(&public_key_raw)
    }
}

/// Sign data using Vault's Transit engine
/// Automatically determines the correct signing parameters based on key type and data size
pub async fn sign_data(
    client: &VaultClient,
    key_name: &str,
    data: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let path = format!("{}/sign/{}", client.config().mount_path, key_name);
    
    // Get key information to determine type
    let key_type = get_key_type(client, key_name).await?;
    
    // Vault expects base64-encoded input
    let input_b64 = base64::engine::general_purpose::STANDARD.encode(data);
    
    let payload = if key_type == "ed25519" {
        // Ed25519: try prehashed=true for 32-byte hash inputs (Blake2b-256)
        // This tells Vault to treat the input as a pre-computed hash
        let is_hash_input = data.len() == 32;
        if is_hash_input {
            json!({
                "input": input_b64,
                "prehashed": true
            })
        } else {
            json!({
                "input": input_b64,
                "prehashed": false
            })
        }
    } else {
        // ECDSA: Use prehashed=false for IOTA compatibility
        // When prehashed=false, Vault applies SHA-256 internally before signing
        // This is compatible with IOTA's signature validation when we pass Blake2b-256 digest
        println!("🔍 ECDSA signing: data size {} bytes, prehashed: false", data.len());
        json!({
            "input": input_b64,
            "prehashed": false
        })
    };

    let response = client.post(&path, &payload).await?;
    
    let signature_b64 = response
        .get("data")
        .and_then(|d| d.get("signature"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| VaultError::Api("Signature not found in response".to_string()))?;

    // Vault signatures are prefixed with "vault:v1:" - remove this prefix
    let signature_data = signature_b64
        .strip_prefix("vault:v1:")
        .unwrap_or(signature_b64);

    base64::engine::general_purpose::STANDARD.decode(signature_data).map_err(VaultError::Base64)
}

/// Get the type of a key from Vault
async fn get_key_type(client: &VaultClient, key_name: &str) -> Result<String, VaultError> {
    let path = format!("{}/keys/{}", client.config().mount_path, key_name);
    
    let response = client.get(&path).await?;
    
    let key_type = response
        .get("data")
        .and_then(|d| d.get("type"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| VaultError::Api("Key type not found in response".to_string()))?;

    Ok(key_type.to_string())
}

/// Check if a key exists in Vault
pub async fn key_exists(
    client: &VaultClient,
    key_name: &str,
) -> Result<bool, VaultError> {
    let path = format!("{}/keys/{}", client.config().mount_path, key_name);
    
    match client.get(&path).await {
        Ok(_) => Ok(true),
        Err(VaultError::Api(ref msg)) if msg.contains("404") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Delete a key from Vault
pub async fn delete_key(
    client: &VaultClient,
    key_name: &str,
) -> Result<(), VaultError> {
    let path = format!("{}/keys/{}", client.config().mount_path, key_name);
    
    // First try to update the key to allow deletion
    let update_payload = json!({
        "deletion_allowed": true
    });
    
    let update_path = format!("{}/keys/{}/config", client.config().mount_path, key_name);
    if let Err(e) = client.post(&update_path, &update_payload).await {
        // If updating fails, it might already be configured for deletion or the key doesn't exist
        // We'll try to delete anyway
        eprintln!("Warning: Could not update key deletion policy: {}", e);
    }
    
    // Now attempt to delete the key
    client.delete(&path).await
}

/// Convert PEM format to DER
fn pem_to_der(pem: &str) -> Result<Vec<u8>, VaultError> {
    // Remove PEM headers and decode base64
    let pem_lines: Vec<&str> = pem.lines().collect();
    let mut base64_data = String::new();
    
    let mut in_key = false;
    for line in pem_lines {
        if line.starts_with("-----BEGIN") {
            in_key = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_key {
            base64_data.push_str(line.trim());
        }
    }
    
    base64::engine::general_purpose::STANDARD.decode(&base64_data).map_err(VaultError::Base64)
}

/// Create DER encoding for Ed25519 public key
/// Ed25519 DER format: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }
fn create_ed25519_der(raw_key: &[u8]) -> Result<Vec<u8>, VaultError> {
    if raw_key.len() != 32 {
        return Err(VaultError::General("Ed25519 public key must be 32 bytes".to_string()));
    }
    
    // Ed25519 OID: 1.3.101.112
    let ed25519_oid = [
        0x30, 0x05, // SEQUENCE (5 bytes)
        0x06, 0x03, // OID (3 bytes)  
        0x2b, 0x65, 0x70 // 1.3.101.112
    ];
    
    // Build the DER structure
    let mut der = Vec::new();
    
    // Outer SEQUENCE
    der.push(0x30); // SEQUENCE tag
    der.push(0x2a); // Length: 42 bytes total (5 + 34 + 3)
    
    // Algorithm identifier SEQUENCE
    der.extend_from_slice(&ed25519_oid);
    
    // BIT STRING containing the public key
    der.push(0x03); // BIT STRING tag
    der.push(0x21); // Length: 33 bytes (32 key bytes + 1 unused bits byte)
    der.push(0x00); // Unused bits: 0
    der.extend_from_slice(raw_key); // 32 bytes of Ed25519 public key
    
    Ok(der)
}