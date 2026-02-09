// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use async_trait::async_trait;
use blake2::Blake2b;
use blake2::Digest;
use iota_interaction::shared_crypto::intent::Intent;
use iota_interaction::shared_crypto::intent::IntentMessage;
use iota_interaction::types::crypto::Ed25519IotaSignature;
use iota_interaction::types::crypto::IotaSignatureInner as _;
use iota_interaction::types::crypto::Secp256k1IotaSignature;
use iota_interaction::types::crypto::Secp256r1IotaSignature;
use iota_interaction::types::crypto::ToFromBytes;
use iota_interaction::IotaKeySignature;
use secret_storage::Signer;

use crate::get_public_key_der;
use crate::signature_scheme_iota::convert_public_key_der_to_iota_public_key;
use crate::signature_scheme_iota::SignatureSchemeInput;
use crate::signature_scheme_iota::SignatureSchemePublicKey;
use crate::signature_scheme_iota::SignatureSchemeSignature;
use crate::AwsKmsSigner;

type Blake2b256 = Blake2b<typenum::U32>;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<IotaKeySignature> for AwsKmsSigner {
    type KeyId = String;

    async fn sign(
        &self,
        data: &SignatureSchemeInput,
    ) -> secret_storage::Result<SignatureSchemeSignature> {
        // Prepare intent message for signing
        let intent_msg = IntentMessage::new(Intent::iota_transaction(), data.clone());
        let bcs_bytes = bcs::to_bytes(&intent_msg).unwrap();

        // Calculate digest to sign - use Blake2b-256 for intent message as per IOTA docs
        // Then ECDSA will internally use SHA-256
        let digest = Blake2b256::digest(&bcs_bytes);

        // signature as returned from AWS
        let signature = self.sign(&digest.to_vec()).await.unwrap();

        // build IOTA signature with public key
        let public_key_iota = Signer::<IotaKeySignature>::public_key(self).await?;
        let iota_signature_bytes = to_iota_signature(&signature, &public_key_iota).unwrap();
        let iota_signature = SignatureSchemeSignature::from_bytes(&iota_signature_bytes).unwrap();

        Ok(iota_signature)
    }

    async fn public_key(&self) -> secret_storage::Result<SignatureSchemePublicKey> {
        let (public_key_der, key_spec) =
            get_public_key_der(&self.client, &self.get_api_key_id()).await?;
        let public_key_iota =
            convert_public_key_der_to_iota_public_key(&public_key_der, &key_spec.try_into()?)
                .unwrap();

        Ok(public_key_iota)
    }

    fn key_id(&self) -> Self::KeyId {
        self.key_id()
    }
}

pub fn to_iota_signature(
    signature: &[u8],
    public_key_iota: &SignatureSchemePublicKey,
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

/// Canonicalize ECDSA signature s value to ensure it's in the lower half
/// For secp256r1, if s > n/2, then s' = n - s
fn canonicalize_s_value_secp256r1(s_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
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

fn canonicalize_s_value_secp256k1(s_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // secp256r1 curve order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    let n_div_2: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
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
