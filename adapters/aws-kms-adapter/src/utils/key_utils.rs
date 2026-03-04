// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Key identification and management utilities

use aws_sdk_kms::types::KeySpec;
use aws_sdk_kms::Client as KmsClient;
use secret_storage::Result;

use crate::AwsKmsError;

pub(crate) async fn get_public_key_der(client: &KmsClient, key_id: &str) -> Result<(Vec<u8>, KeySpec)> {
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
    })
    .unwrap();

  let public_key_der = public_key_response
    .public_key
    .ok_or_else(|| AwsKmsError::General("No public key returned from KMS".to_string()))?
    .into_inner();

  // Get the actual KMS key ID for logging and validation
  let actual_key_id = public_key_response.key_id.as_deref().unwrap_or("unknown");

  // Verify it's the expected key type
  if let Some(key_usage) = public_key_response.key_usage {
    if key_usage != aws_sdk_kms::types::KeyUsageType::SignVerify {
      return Err(
        AwsKmsError::General(format!(
          "Key {} (actual ID: {}) is not for signing, got usage: {:?}",
          key_id, actual_key_id, key_usage
        ))
        .into(),
      );
    }
  }

  let key_spec = public_key_response
    .key_spec
    .ok_or_else(|| AwsKmsError::General(format!("Key {} is missing KeySpec information", key_id)))?;

  Ok((public_key_der, key_spec.clone()))
}
