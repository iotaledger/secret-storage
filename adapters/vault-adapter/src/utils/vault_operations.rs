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
        "allow_plaintext_backup": false
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

    let public_key_pem = keys
        .get(&latest_version.to_string())
        .and_then(|v| v.get("public_key"))
        .and_then(|pk| pk.as_str())
        .ok_or_else(|| VaultError::Api("Public key not found".to_string()))?;

    // Convert PEM to DER format
    let public_key_der = pem_to_der(public_key_pem)?;
    Ok(public_key_der)
}

/// Sign data using Vault's Transit engine
pub async fn sign_data(
    client: &VaultClient,
    key_name: &str,
    data: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let path = format!("{}/sign/{}", client.config().mount_path, key_name);
    
    // Vault expects base64-encoded input
    let input_b64 = base64::engine::general_purpose::STANDARD.encode(data);
    
    let payload = json!({
        "input": input_b64,
        "signature_algorithm": "pkcs1v15"
    });

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