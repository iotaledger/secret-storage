// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use blake2::{Blake2b, Digest};
use iota_interaction::{
    shared_crypto::intent::{Intent, IntentMessage},
    types::crypto::{Signature, SignatureScheme as IotaSignatureScheme, ToFromBytes},
    IotaKeySignature, OptionalSync,
};
use secret_storage::{Error, Result, SignatureScheme, Signer};

use crate::{sign, AwsKmsSignatureScheme, AwsKmsSigner};

type Blake2b256 = Blake2b<typenum::U32>;

type IotaKeySignatureInput = <IotaKeySignature as SignatureScheme>::Input;
type IotaKeySignaturePublicKey = <IotaKeySignature as SignatureScheme>::PublicKey;
type IotaKeySignatureSignature = <IotaKeySignature as SignatureScheme>::Signature;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<IotaKeySignature> for AwsKmsSigner {
    type KeyId = String;

    async fn sign(
        &self,
        data: &IotaKeySignatureInput,
    ) -> secret_storage::Result<IotaKeySignatureSignature> {
        // Prepare intent message for signing
        let intent_msg = IntentMessage::new(Intent::iota_transaction(), data.clone());
        let bcs_bytes = bcs::to_bytes(&intent_msg).unwrap();

        // Calculate digest to sign - use Blake2b-256 for intent message as per IOTA docs
        // Then ECDSA will internally use SHA-256
        let digest = Blake2b256::digest(&bcs_bytes);

        // let signature = Signer::<AwsKmsSignatureScheme>::sign(self, &digest.to_vec()).await?;
        let signature = sign(
            &self.client,
            &self.get_api_key_id(),
            &digest.to_vec(),
            &self.signing_algorithm,
        )
        .await
        .unwrap();
        let public_key_iota = Signer::<IotaKeySignature>::public_key(self).await?;

        let compressed_pubkey =
            key_utils::to_iota_signature(&signature, &public_key_iota, &self.signing_algorithm)
                .unwrap();

        let iota_signature = Signature::from_bytes(&compressed_pubkey).unwrap();

        Ok(iota_signature)
    }

    // Currently copy of other signing fn, as information from AWS is not available anymore
    // after converting it to AwsKeySignatureScheme PublicKey
    // TODO: decide wether to keep other signature in support and refactor pub key retrieval functions
    // to retrieve with optional conversion.
    async fn public_key(&self) -> secret_storage::Result<IotaKeySignaturePublicKey> {
        let pk = get_public_key_iota(&self.client, &self.get_api_key_id()).await?;
        Ok(pk)

        // // let public_key_der = Signer::<AwsKmsSignatureScheme>::public_key(self).await?;
        // // let public_key =
        // //     key_utils::convert_public_key_der_to_iota_public_key(&public_key_der).unwrap();

        // // Ok(public_key)

        // // Get the appropriate key identifier for AWS KMS API
        // let key_id = self.get_api_key_id();

        // // Get public key from AWS KMS
        // let public_key_response = self
        //     .client
        //     .get_public_key()
        //     .key_id(&key_id)
        //     .send()
        //     .await
        //     .map_err(|e| {
        //         secret_storage::Error::Other(anyhow::anyhow!(
        //             "Failed to get public key from AWS KMS for key {}: {}",
        //             key_id,
        //             e
        //         ))
        //     })?;

        // let public_key_der = public_key_response
        //     .public_key
        //     .ok_or_else(|| {
        //         secret_storage::Error::Other(anyhow::anyhow!("No public key returned from AWS KMS"))
        //     })?
        //     .into_inner();

        // // TODO: skip verification for now, as types might vary
        // // Verify it's the expected key type (secp256r1)
        // if let Some(key_spec) = public_key_response.key_spec {
        //     // if key_spec != aws_sdk_kms::types::KeySpec::EccNistP256 {
        //     //     return Err(secret_storage::Error::Other(anyhow::anyhow!(
        //     //         "Key {} is not secp256r1, got spec: {:?}",
        //     //         key_id,
        //     //         key_spec
        //     //     )));
        //     // }
        //     // if key_spec != aws_sdk_kms::types::KeySpec::EccNistEdwards25519 {
        //     //     return Err(secret_storage::Error::Other(anyhow::anyhow!(
        //     //         "Key {} is not EccNistEdwards25519, got spec: {:?}",
        //     //         key_id,
        //     //         key_spec
        //     //     ))
        //     //     .into());
        //     // }
        // }

        // if let Some(key_usage) = public_key_response.key_usage {
        //     if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
        //         return Err(secret_storage::Error::Other(anyhow::anyhow!(
        //             "Key {} is not for signing, got usage: {:?}",
        //             key_id,
        //             key_usage
        //         )));
        //     }
        // }

        // let public_key_iota = convert_public_key_der_to_iota_public_key(&public_key_der).unwrap();

        // Ok(public_key_iota)
    }

    fn key_id(&self) -> Self::KeyId {
        todo!()
    }
}

// TODO: move to shared space
mod key_utils {
    use std::error::Error;

    use aws_sdk_kms::{
        types::{KeySpec, SigningAlgorithmSpec},
        Client,
    };
    use iota_interaction::types::crypto::{
        Ed25519IotaSignature, IotaSignatureInner as _, PublicKey, Secp256k1IotaSignature,
        Secp256r1IotaSignature, Signature, SignatureScheme as IotaSignatureScheme,
    };
    use pkcs8::DecodePublicKey as _;
    use secret_storage::SignatureScheme;

    use crate::{signature_scheme_iota::signer_iota::IotaKeySignaturePublicKey, AwsKmsError};

    pub fn der_to_compressed_public_key(public_key_der: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Extract raw public key to determine signature type
        let raw_pubkey = extract_raw_public_key_from_der(&public_key_der).unwrap();

        if raw_pubkey.len() == 65 && raw_pubkey[0] == 0x04 {
            // Compress public key
            let compressed_pubkey = compress_public_key(&raw_pubkey).unwrap();
            Ok(compressed_pubkey)
        } else {
            return Err(format!(
                "Unsupported public key format: {} bytes. Only ECDSA secp256r1 (65 bytes uncompressed) is supported",
                raw_pubkey.len()
            ).into());
        }
    }

    pub fn to_iota_signature(
        signature: &[u8],
        public_key_iota: &IotaKeySignaturePublicKey,
        _signing_algorithm: &SigningAlgorithmSpec,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let (r_bytes, s_bytes) = match public_key_iota.scheme() {
            Secp256r1IotaSignature::SCHEME => {
                let signature = p256::ecdsa::Signature::from_der(signature).unwrap();
                let (r, s) = signature.split_bytes();
                // Canonicalize s value for IOTA compliance
                let s_canonical = canonicalize_s_value_secp256r1(&s)?;

                (r.to_vec(), s_canonical.to_vec())
            }
            Secp256k1IotaSignature::SCHEME => {
                let signature = k256::ecdsa::Signature::from_der(signature).unwrap();
                let (r, s) = signature.split_bytes();
                // Canonicalize s value for IOTA compliance
                let s_canonical = canonicalize_s_value_secp256k1(&s)?;

                (r.to_vec(), s_canonical.to_vec())
            }
            Ed25519IotaSignature::SCHEME => {
                let signature = ed25519::Signature::from_slice(signature).unwrap();

                (signature.r_bytes().to_vec(), signature.s_bytes().to_vec())
            }
            scheme => return Err(format!("Unsupported public key scheme: {}", scheme).into()),
        };

        // // Canonicalize s value for IOTA compliance
        // let s_canonical = canonicalize_s_value(&s_bytes)?;

        // Create IOTA signature format: [scheme_flag:1][r:32][s:32][pubkey_compressed:33]
        let mut sig_bytes = vec![public_key_iota.flag()];

        // // Ensure r and s are exactly 32 bytes
        let mut r_32 = [0u8; 32];
        let mut s_32 = [0u8; 32];
        let r_len = std::cmp::min(r_bytes.len(), 32);
        let s_len = std::cmp::min(s_bytes.len(), 32);
        r_32[32 - r_len..].copy_from_slice(&r_bytes[r_bytes.len() - r_len..]);
        s_32[32 - s_len..].copy_from_slice(&s_bytes[s_bytes.len() - s_len..]);
        s_32[32 - s_len..].copy_from_slice(&s_bytes[s_bytes.len() - s_len..]);

        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);
        sig_bytes.extend_from_slice(public_key_iota.as_ref());

        Ok(sig_bytes)
    }

    /// Extract raw public key bytes from DER encoding
    /// Only supports ECDSA secp256r1 (65 bytes)
    pub fn extract_raw_public_key_from_der(der_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if der_bytes.len() < 10 {
            return Err("Invalid DER: too short".into());
        }

        // Look for the bit string tag (0x03) and extract the ECDSA secp256r1 public key
        for i in 0..der_bytes.len().saturating_sub(10) {
            if der_bytes[i] == 0x03 {
                // Found bit string tag, check length byte
                if let Some(&length) = der_bytes.get(i + 1) {
                    if length == 0x42 && der_bytes.get(i + 2) == Some(&0x00) {
                        // ECDSA secp256r1 case: bit string with 66 bytes (0x42 = 66 decimal)
                        // Next byte is 0x00 (unused bits), then 65 bytes of public key
                        if i + 3 + 65 <= der_bytes.len() {
                            return Ok(der_bytes[i + 3..i + 3 + 65].to_vec());
                        }
                    }
                }
            }
        }

        Err("Could not extract ECDSA secp256r1 public key from DER - invalid format or unsupported key type".into())
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

    pub fn convert_public_key_der_to_iota_public_key(
        _public_key_der: &Vec<u8>,
    ) -> Result<IotaKeySignaturePublicKey, Box<dyn Error>> {
        panic!("outdated fn call");
        #[allow(unreachable_code)]
        let compressed_pubkey = der_to_compressed_public_key(&_public_key_der).unwrap();

        let public_key = IotaKeySignaturePublicKey::try_from_bytes(
            IotaSignatureScheme::Secp256r1,
            &compressed_pubkey,
        )
        .unwrap();

        Ok(public_key)
    }

    // /// Parse DER signature into r and s components with canonicalization
    // fn parse_der_signature(der_signature: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    //     // Very basic DER parsing for ECDSA signatures
    //     // DER format: 30 [length] 02 [r_length] [r_bytes] 02 [s_length] [s_bytes]

    //     if der_signature.len() < 8 || der_signature[0] != 0x30 {
    //         return Err("Invalid DER signature format".into());
    //     }

    //     let mut pos = 2; // Skip 30 and total length

    //     // Parse r
    //     if der_signature[pos] != 0x02 {
    //         return Err("Expected INTEGER tag for r".into());
    //     }
    //     pos += 1;
    //     let r_len = der_signature[pos] as usize;
    //     pos += 1;
    //     let mut r_bytes = der_signature[pos..pos + r_len].to_vec();
    //     pos += r_len;

    //     // Remove leading zero if present (DER encoding requirement)
    //     if r_bytes.len() > 32 && r_bytes[0] == 0x00 {
    //         r_bytes = r_bytes[1..].to_vec();
    //     }

    //     // Pad to 32 bytes if needed
    //     while r_bytes.len() < 32 {
    //         r_bytes.insert(0, 0x00);
    //     }

    //     // Parse s
    //     if der_signature[pos] != 0x02 {
    //         return Err("Expected INTEGER tag for s".into());
    //     }
    //     pos += 1;
    //     let s_len = der_signature[pos] as usize;
    //     pos += 1;
    //     let mut s_bytes = der_signature[pos..pos + s_len].to_vec();

    //     // Remove leading zero if present
    //     if s_bytes.len() > 32 && s_bytes[0] == 0x00 {
    //         s_bytes = s_bytes[1..].to_vec();
    //     }

    //     // Pad to 32 bytes if needed
    //     while s_bytes.len() < 32 {
    //         s_bytes.insert(0, 0x00);
    //     }

    //     // Canonicalize s value (ensure it's low)
    //     s_bytes = canonicalize_s_value(&s_bytes)?;

    //     Ok((r_bytes, s_bytes))
    // }

    /// Canonicalize ECDSA signature s value to ensure it's in the lower half
    /// For secp256r1, if s > n/2, then s' = n - s
    fn canonicalize_s_value_secp256r1(s_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // secp256r1 curve order: n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        let n_div_2: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61,
            0x7e, 0x31, 0x92, 0xa8,
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

    fn canonicalize_s_value_secp256k1(s_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // secp256r1 curve order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        let n_div_2: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46,
            0x68, 0x1b, 0x20, 0xa0,
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
            // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            let n: [u8; 32] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
                0xd0, 0x36, 0x41, 0x41,
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

    pub async fn get_public_key_iota(
        client: &Client,
        key_id: &String,
    ) -> Result<IotaKeySignaturePublicKey, AwsKmsError> {
        // AWS KMS get_public_key accepts both aliases and KMS key IDs
        let public_key_response = client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| {
                AwsKmsError::General(format!(
                    "Failed to get public key from KMS: {}",
                    e.into_source().unwrap()
                ))
            })?;

        let public_key_der = public_key_response
            .public_key
            .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
            .into_inner();

        // Get the actual KMS key ID for logging and validation
        let actual_key_id = public_key_response.key_id.as_deref().unwrap_or("unknown");

        // Verify it's the expected key type
        if let Some(key_usage) = public_key_response.key_usage {
            if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
                return Err(AwsKmsError::General(format!(
                    "Key {} (actual ID: {}) is not for signing, got usage: {:?}",
                    key_id, actual_key_id, key_usage
                ))
                .into());
            }
        }

        let public_key = match public_key_response.key_spec {
            Some(KeySpec::EccNistEdwards25519) => {
                let public_key_bytes =
                    <ed25519::pkcs8::PublicKeyBytes as pkcs8::DecodePublicKey>::from_public_key_der(&public_key_der)
                    .unwrap();

                PublicKey::try_from_bytes(
                    IotaSignatureScheme::ED25519,
                    &public_key_bytes.to_bytes(),
                )
                .unwrap()
            }
            Some(KeySpec::EccNistP256) => {
                let decoded = p256::PublicKey::from_public_key_der(&public_key_der).unwrap();
                let sec1_bytes = decoded.to_sec1_bytes();
                let pk =
                    PublicKey::try_from_bytes(IotaSignatureScheme::Secp256r1, &sec1_bytes).unwrap();

                pk
            }
            Some(KeySpec::EccSecgP256K1) => {
                let decoded = k256::PublicKey::from_public_key_der(&public_key_der).unwrap();
                let sec1_bytes = decoded.to_sec1_bytes();
                let pk =
                    PublicKey::try_from_bytes(IotaSignatureScheme::Secp256k1, &sec1_bytes).unwrap();

                pk
            }
            Some(key_spec) => {
                return Err(AwsKmsError::General(format!(
                    "Key {} uses unsupported spec: {:?}",
                    key_id, key_spec
                ))
                .into());
            }
            None => {
                return Err(AwsKmsError::General(format!(
                    "Key {} is missing KeySpec information",
                    key_id
                ))
                .into());
            }
        };

        Ok(public_key)
    }
}

pub use key_utils::convert_public_key_der_to_iota_public_key;
pub use key_utils::get_public_key_iota;
