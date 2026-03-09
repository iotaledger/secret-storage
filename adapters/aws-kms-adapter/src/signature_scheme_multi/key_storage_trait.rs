// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;

use aws_sdk_kms::types::KeyState;
use multi_schema::KeyType;
use multi_schema::SignatureSchemeMulti;
use multi_schema::SignatureSchemeMultiPublicKey;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions;
use secret_storage::Result;
use secret_storage::SignatureScheme as SecretStorageSignatureScheme;

use crate::key_utils::get_public_key_der;
use crate::AwsKmsSigner;
use crate::AwsKmsStorage;
use crate::KeySpec;

const KEY_DELETION_PENDING_WINDOW_IN_DAYS: i32 = 7;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGenerate<SignatureSchemeMulti, String> for AwsKmsStorage {
  type Options = KeyType;

  async fn generate_key_with_options(
    &self,
    options: KeyType,
  ) -> Result<(
    String,
    <SignatureSchemeMulti as SecretStorageSignatureScheme>::PublicKey,
  )> {
    let key_spec: KeySpec = options.try_into().unwrap();

    let (kms_key_id, public_key_der) = self.generate_key(key_spec).await.unwrap();

    let public_key_multi = SignatureSchemeMultiPublicKey {
      bytes: public_key_der,
      key_type: key_spec.try_into().unwrap(),
    };

    // Return the original alias as the key identifier (without 'alias/' prefix for user display)
    Ok((kms_key_id, public_key_multi))
  }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGet<SignatureSchemeMulti, String> for AwsKmsStorage {
  async fn public_key(
    &self,
    key_id: &String,
  ) -> Result<<SignatureSchemeMulti as SecretStorageSignatureScheme>::PublicKey> {
    let (public_key_der, key_spec_aws) = get_public_key_der(&self.client, key_id).await?;
    let key_spec_adapter: KeySpec = key_spec_aws.try_into().unwrap();

    Ok(SignatureSchemeMultiPublicKey {
      bytes: public_key_der,
      key_type: key_spec_adapter.try_into().unwrap(),
    })
  }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyDelete<String> for AwsKmsStorage {
  async fn delete(&self, key_id: &String) -> Result<()> {
    self
      .client
      .schedule_key_deletion()
      .key_id(key_id)
      .pending_window_in_days(KEY_DELETION_PENDING_WINDOW_IN_DAYS)
      .send()
      .await
      .unwrap();

    Ok(())
  }
}

/// KeyExists trait is a trait that is used to check if a key pair with given id exists in the key store.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyExist<String> for AwsKmsStorage {
  async fn exist(&self, key_id: &String) -> Result<bool> {
    match self.client.describe_key().key_id(key_id).send().await {
      Ok(response) => {
        if let Some(metadata) = response.key_metadata {
          let is_enabled = metadata.enabled;
          let is_valid = !matches!(
            metadata.key_state,
            Some(KeyState::PendingDeletion) | Some(KeyState::Disabled)
          );
          Ok(is_enabled && is_valid)
        } else {
          Ok(false)
        }
      }
      Err(_) => Ok(false), // Key doesn't exist or we can't access it
    }
  }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeySignWithOptions<SignatureSchemeMulti, String> for AwsKmsStorage {
  type Signer = AwsKmsSigner;
  type Options = KeyType;
  fn get_signer_with_options(&self, key_id: &String, signature_type: &KeyType) -> Result<Self::Signer> {
    let signer: AwsKmsSigner =
      AwsKmsStorage::get_signer_with_key_spec(self, key_id, signature_type.clone().try_into().unwrap())?;
    Ok(signer)
  }
}
