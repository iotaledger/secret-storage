// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use aws_sdk_kms::{types::SigningAlgorithmSpec, Client as KmsClient};
use secret_storage_core::{Result, Signer};

use crate::AwsKmsSignatureScheme;
use crate::utils::key_utils::is_alias;

/// AWS KMS signer implementation
pub struct AwsKmsSigner {
    client: KmsClient,
    alias: String,
    kms_key_id: String,
    signing_algorithm: SigningAlgorithmSpec,
}

impl AwsKmsSigner {
    /// Create new AWS KMS signer
    /// key_identifier can be either an alias or a KMS key ID/ARN
    pub fn new(client: KmsClient, key_identifier: String, kms_key_id: String) -> Self {
        // Determine if this is an alias or a KMS key ID/ARN
        let (alias, actual_kms_key_id) = if is_alias(&key_identifier) {
            // It's an alias - keep it as-is and use the resolved key ID
            (key_identifier, kms_key_id)
        } else {
            // It's a KMS key ID or ARN, so alias is empty and we use the key_identifier as kms_key_id
            (String::new(), key_identifier)
        };

        Self {
            client,
            alias,
            kms_key_id: actual_kms_key_id,
            // Default to ECDSA_SHA_256 for P-256 keys
            signing_algorithm: SigningAlgorithmSpec::EcdsaSha256,
        }
    }

    /// Set signing algorithm
    pub fn with_signing_algorithm(mut self, algorithm: SigningAlgorithmSpec) -> Self {
        self.signing_algorithm = algorithm;
        self
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl Signer<AwsKmsSignatureScheme> for AwsKmsSigner {
    type KeyId = String;

    async fn sign(&self, data: &Vec<u8>) -> Result<Vec<u8>> {

        // Use the most appropriate key identifier (prefer alias if available)
        let key_id = if !self.alias.is_empty() {
            &self.alias
        } else {
            &self.kms_key_id
        };

        // Perform AWS KMS signing operation
        let sign_response = self
            .client
            .sign()
            .key_id(key_id)
            .message(aws_sdk_kms::primitives::Blob::new(data.clone()))
            .message_type(aws_sdk_kms::types::MessageType::Raw)
            .signing_algorithm(self.signing_algorithm.clone())
            .send()
            .await
            .map_err(|e| {
                secret_storage_core::Error::Other(anyhow::anyhow!(
                    "AWS KMS signing failed for key {}: {}",
                    key_id, e
                ))
            })?;

        let signature = sign_response
            .signature
            .ok_or_else(|| {
                secret_storage_core::Error::Other(anyhow::anyhow!(
                    "No signature returned from AWS KMS"
                ))
            })?
            .into_inner();


        Ok(signature)
    }

    async fn public_key(&self) -> Result<Vec<u8>> {

        // Use the most appropriate key identifier (prefer alias if available)
        let key_id = if !self.alias.is_empty() {
            &self.alias
        } else {
            &self.kms_key_id
        };

        // Get public key from AWS KMS
        let public_key_response = self
            .client
            .get_public_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| {
                secret_storage_core::Error::Other(anyhow::anyhow!(
                    "Failed to get public key from AWS KMS for key {}: {}",
                    key_id, e
                ))
            })?;

        let public_key_der = public_key_response
            .public_key
            .ok_or_else(|| {
                secret_storage_core::Error::Other(anyhow::anyhow!(
                    "No public key returned from AWS KMS"
                ))
            })?
            .into_inner();

        // Verify it's the expected key type (secp256r1)
        if let Some(key_spec) = public_key_response.key_spec {
            if key_spec != aws_sdk_kms::types::KeySpec::EccNistP256 {
                return Err(secret_storage_core::Error::Other(anyhow::anyhow!(
                    "Key {} is not secp256r1, got spec: {:?}",
                    key_id, key_spec
                )));
            }
        }

        if let Some(key_usage) = public_key_response.key_usage {
            if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
                return Err(secret_storage_core::Error::Other(anyhow::anyhow!(
                    "Key {} is not for signing, got usage: {:?}",
                    key_id, key_usage
                )));
            }
        }


        Ok(public_key_der)
    }

    fn key_id(&self) -> Self::KeyId {
        // Return the most appropriate identifier
        if !self.alias.is_empty() {
            self.alias.clone()
        } else {
            self.kms_key_id.clone()
        }
    }
}
