// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use aws_sdk_kms::Client as KmsClient;

use crate::KeySpec;

/// AWS KMS signer implementation
pub struct AwsKmsSigner {
  pub(crate) client: KmsClient,
  pub(crate) key_spec: KeySpec,
  kms_key_id: String,
}

/// Defines general instance handling.
///
/// As we don't expose signing without the [secret_storage::Singer] trait, signing logic is located
/// in that traits implementation.
impl AwsKmsSigner {
  /// Create new AWS KMS signer
  pub fn new(client: KmsClient, kms_key_id: String, key_spec: KeySpec) -> Self {
    Self {
      client,
      kms_key_id,
      key_spec,
    }
  }

  pub(crate) fn key_id(&self) -> String {
    self.kms_key_id.clone()
  }
}
