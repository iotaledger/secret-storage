// Copyright 2020-2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use iota_interaction::IotaKeySignature;
use iota_interaction::types::crypto::SignatureScheme as IotaSignatureScheme;
use pkcs8::DecodePublicKey as _;
use secret_storage::Error as SecretStorageError;
use secret_storage::SignatureScheme;
use typed_key_signature::KeyType;

pub(crate) type IotaKeySignatureInput = <IotaKeySignature as SignatureScheme>::Input;
pub(crate) type IotaKeySignaturePublicKey = <IotaKeySignature as SignatureScheme>::PublicKey;
pub(crate) type IotaKeySignatureSignature = <IotaKeySignature as SignatureScheme>::Signature;

pub fn convert_public_key_der_to_iota_public_key(
    public_key_der: &[u8],
    key_type: &KeyType,
) -> secret_storage::Result<IotaKeySignaturePublicKey> {
    let public_key = match key_type {
        KeyType::Ed25519DerEncoded => {
            let public_key_bytes =
                <ed25519::pkcs8::PublicKeyBytes as pkcs8::DecodePublicKey>::from_public_key_der(
                    public_key_der,
                )
                .map_err(|e| {
                    SecretStorageError::Other(anyhow!("failed to decode ED25519 public key; {e}"))
                })?;

            IotaKeySignaturePublicKey::try_from_bytes(
                IotaSignatureScheme::ED25519,
                &public_key_bytes.to_bytes(),
            )
            .map_err(|e| {
                SecretStorageError::Other(anyhow!(
                    "failed to create IOTA public key from bytes; {e}"
                ))
            })?
        }
        KeyType::Secp256r1DerEncoded => {
            let decoded = p256::PublicKey::from_public_key_der(public_key_der).map_err(|e| {
                SecretStorageError::Other(anyhow!("failed to decode SECP256R1 public key; {e}"))
            })?;
            let sec1_bytes = decoded.to_sec1_bytes();
            IotaKeySignaturePublicKey::try_from_bytes(IotaSignatureScheme::Secp256r1, &sec1_bytes)
                .map_err(|e| {
                SecretStorageError::Other(anyhow!(
                    "failed to create IOTA public key from bytes; {e}"
                ))
            })?
        }
        KeyType::Secp256k1DerEncoded => {
            let decoded = k256::PublicKey::from_public_key_der(public_key_der).map_err(|e| {
                SecretStorageError::Other(anyhow!("failed to decode SECP256K1 public key; {e}"))
            })?;
            let sec1_bytes = decoded.to_sec1_bytes();
            IotaKeySignaturePublicKey::try_from_bytes(IotaSignatureScheme::Secp256k1, &sec1_bytes)
                .map_err(|e| {
                SecretStorageError::Other(anyhow!(
                    "failed to create IOTA public key from bytes; {e}"
                ))
            })?
        }
        other => {
            return Err(SecretStorageError::Other(anyhow!(
                "unsupported public key type: {other}"
            )));
        }
    };

    Ok(public_key)
}
