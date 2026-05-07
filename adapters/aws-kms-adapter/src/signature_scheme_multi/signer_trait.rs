// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use async_trait::async_trait;
use aws_sdk_kms::types::SigningAlgorithmSpec;
use k256::ecdsa::Signature as K256Signature;
use multi_signature_scheme::SignatureSchemeMulti;
use multi_signature_scheme::SignatureSchemeMultiPublicKey;
use multi_signature_scheme::SignatureSchemeMultiSignature;
use p256::ecdsa::Signature as P256Signature;
use secret_storage::Signer;

use crate::key_utils::get_public_key_der;
use crate::AwsKmsSigner;
use crate::KeySpec;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<SignatureSchemeMulti> for AwsKmsSigner {
  type KeyId = String;

  async fn sign(&self, data: &Vec<u8>) -> secret_storage::Result<SignatureSchemeMultiSignature> {
    let key_id = self.key_id();

    // Perform AWS KMS signing operation
    let sign_response = self
      .client
      .sign()
      .key_id(key_id.clone())
      .message(aws_sdk_kms::primitives::Blob::new(data.clone()))
      .message_type(aws_sdk_kms::types::MessageType::Raw)
      .signing_algorithm(get_signing_algorithm_for_key_spec(self.key_spec))
      .send()
      .await
      .map_err(|e| {
        secret_storage::Error::Other(anyhow!(
          "AWS KMS signing failed for key {}{}",
          key_id,
          e.as_service_error()
            .map(|se| format!(": {}", &se.meta()))
            .unwrap_or_default()
        ))
      })?;

    let signature = sign_response
      .signature
      .ok_or_else(|| secret_storage::Error::Other(anyhow!("No signature returned from AWS KMS")))?
      .into_inner();

    let signature = match self.key_spec {
      KeySpec::EccNistP256 => P256Signature::from_der(&signature)
        .map_err(|e| {
          secret_storage::Error::Other(anyhow!(
            "Failed to parse P256Signature from AWS KMS response; {}",
            e,
          ))
        })?
        .to_vec(),
      KeySpec::EccSecgP256K1 => K256Signature::from_der(&signature)
        .map_err(|e| {
          secret_storage::Error::Other(anyhow!(
            "Failed to parse K256Signature from AWS KMS response; {}",
            e,
          ))
        })?
        .to_vec(),
      _ => signature,
    };

    Ok(SignatureSchemeMultiSignature::new(signature, self.key_spec.try_into()?))
  }

  async fn public_key(&self) -> secret_storage::Result<SignatureSchemeMultiPublicKey> {
    let (public_key_der, key_spec_aws) = get_public_key_der(&self.client, &self.key_id()).await?;
    let key_spec_adapter: KeySpec = key_spec_aws.try_into()?;

    Ok(SignatureSchemeMultiPublicKey::new(
      public_key_der,
      key_spec_adapter.try_into()?,
    ))
  }

  fn key_id(&self) -> Self::KeyId {
    self.key_id()
  }
}

/// Gets signing algorithms for a given key type (spec).
///
/// Current signing behavior decides on pre-defined signing algorithms by given key type (spec).
fn get_signing_algorithm_for_key_spec(key_spec: KeySpec) -> SigningAlgorithmSpec {
  match key_spec {
    KeySpec::EccNistEdwards25519 => SigningAlgorithmSpec::Ed25519Sha512,
    KeySpec::EccNistP256 => SigningAlgorithmSpec::EcdsaSha256,
    KeySpec::EccSecgP256K1 => SigningAlgorithmSpec::EcdsaSha256,
  }
}
