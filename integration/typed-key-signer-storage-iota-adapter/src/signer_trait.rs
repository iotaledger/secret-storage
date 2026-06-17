// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use anyhow::anyhow;
use async_trait::async_trait;
use blake2::Blake2b;
use blake2::Digest;
use fastcrypto::traits::ToFromBytes;
use iota_interaction::OptionalSync;
use iota_interaction::types::crypto::Ed25519IotaSignature;
use iota_interaction::types::crypto::IotaSignatureInner as _;
use iota_interaction::types::crypto::Secp256k1IotaSignature;
use iota_interaction::types::crypto::Secp256r1IotaSignature;
use iota_sdk_types::Intent;
use iota_sdk_types::IntentMessage;
use secret_storage::Error as SecretStorageError;
use secret_storage::Signer;
use typed_key_signature::TypedKeySignature;

use crate::signer::IotaCompatibleSigner;
use crate::utils::IotaKeySignatureInput;
use crate::utils::IotaKeySignaturePublicKey;
use crate::utils::IotaKeySignatureSignature;
use crate::utils::convert_public_key_der_to_iota_public_key;
use iota_interaction::IotaKeySignature;

type Blake2b256 = Blake2b<typenum::U32>;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TSigner, TKeyId> Signer<IotaKeySignature> for IotaCompatibleSigner<TSigner>
where
    TSigner: Signer<TypedKeySignature, KeyId = TKeyId> + OptionalSync,
    TKeyId: Into<String>,
{
    type KeyId = String;

    async fn sign(
        &self,
        data: &IotaKeySignatureInput,
    ) -> secret_storage::Result<IotaKeySignatureSignature> {
        // Prepare intent message for signing
        let intent_msg = IntentMessage::new(Intent::iota_transaction(), data.clone());
        let bcs_bytes = bcs::to_bytes(&intent_msg).map_err(|e| {
            SecretStorageError::Other(anyhow!("failed to serialize intent message; {e}"))
        })?;

        // Calculate digest to sign - use Blake2b-256 for intent message as per IOTA docs
        // Then ECDSA will internally use SHA-256
        let digest = Blake2b256::digest(&bcs_bytes);

        // signature as returned from AWS
        let signature = self.inner.sign(&digest.to_vec()).await?;

        // build IOTA signature with public key
        let public_key_iota = Signer::<IotaKeySignature>::public_key(self).await?;
        let iota_signature_bytes =
            iota_signature_from_der(signature.bytes(), &public_key_iota).map_err(|e| {
                SecretStorageError::Other(anyhow!("failed to convert to IOTA signature; {e}"))
            })?;
        let iota_signature =
            IotaKeySignatureSignature::from_bytes(&iota_signature_bytes).map_err(|e| {
                SecretStorageError::Other(anyhow!(
                    "failed to create IOTA signature from bytes; {e}"
                ))
            })?;

        Ok(iota_signature)
    }

    async fn public_key(&self) -> secret_storage::Result<IotaKeySignaturePublicKey> {
        let public_key = self.inner.public_key().await?;

        let public_key_iota =
            convert_public_key_der_to_iota_public_key(public_key.bytes(), public_key.key_type())?;

        Ok(public_key_iota)
    }

    fn key_id(&self) -> Self::KeyId {
        self.inner.key_id().into()
    }
}

pub fn iota_signature_from_der(
    signature: &[u8],
    public_key_iota: &IotaKeySignaturePublicKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let scheme = public_key_iota.scheme().to_string();
    let (r_bytes, s_bytes) = if scheme == Secp256r1IotaSignature::SCHEME.to_string() {
        let signature = p256::ecdsa::Signature::from_der(signature)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let (r, s) = signature.split_bytes();
        (r.to_vec(), s.to_vec())
    } else if scheme == Secp256k1IotaSignature::SCHEME.to_string() {
        let signature = k256::ecdsa::Signature::from_der(signature)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let (r, s) = signature.split_bytes();
        (r.to_vec(), s.to_vec())
    } else if scheme == Ed25519IotaSignature::SCHEME.to_string() {
        let signature = ed25519::Signature::from_slice(signature)?;

        (signature.r_bytes().to_vec(), signature.s_bytes().to_vec())
    } else {
        return Err(format!("Unsupported public key scheme: {}", scheme).into());
    };

    let sig_bytes = serialize_iota_signature(public_key_iota, &r_bytes, &s_bytes);

    Ok(sig_bytes)
}

pub fn serialize_iota_signature(
    public_key_iota: &IotaKeySignaturePublicKey,
    r_bytes: &[u8],
    s_bytes: &[u8],
) -> Vec<u8> {
    // IOTA signature format: [scheme_flag:1][r:32][s:32][pubkey_compressed:33]
    let mut sig_bytes = vec![public_key_iota.flag()];
    sig_bytes.extend_from_slice(r_bytes);
    sig_bytes.extend_from_slice(s_bytes);
    sig_bytes.extend_from_slice(public_key_iota.as_ref());
    sig_bytes
}
