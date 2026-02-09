// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use iota_interaction::IotaKeySignature;

use secret_storage::{
    KeyGenerate, KeyGet, KeySign, Result, SignatureScheme as SecretStorageSignatureScheme,
};

use crate::{
    get_public_key_der, signature_scheme_iota::convert_public_key_der_to_iota_public_key,
    AwsKmsKeyOptions, AwsKmsStorage, KeySpec,
};

// Similar to IotaSigner, currently copy of other signing fn, as information from AWS is not available anymore
// after converting it to AwsKeySignatureScheme PublicKey
// TODO: decide wether to keep other signature in support and refactor pub key retrieval functions
// to retrieve with optional conversion.
// TODO: shift away from `String` for key_id or not?
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGenerate<IotaKeySignature, String> for AwsKmsStorage {
    type Options = AwsKmsKeyOptions;

    async fn generate_key_with_options(
        &self,
        options: Self::Options,
    ) -> Result<(
        String,
        <IotaKeySignature as SecretStorageSignatureScheme>::PublicKey,
    )> {
        let key_spec: KeySpec = options
            .key_spec
            .clone()
            .and_then(|adapter_key_spec| Some(adapter_key_spec.try_into()))
            .transpose()
            .unwrap()
            .unwrap(); // TODO: proper error on undefined

        let (kms_key_id, public_key_der) = self.generate_key(options).await.unwrap();

        // Get the public key immediately after creation using the alias
        let public_key_iota =
            convert_public_key_der_to_iota_public_key(&public_key_der, &key_spec).unwrap();

        // Return the original alias as the key identifier (without 'alias/' prefix for user display)
        Ok((kms_key_id, public_key_iota))
    }
}

impl KeySign<IotaKeySignature, String> for AwsKmsStorage {
    fn get_signer(
        &self,
        key_id: &String,
    ) -> Result<impl secret_storage::Signer<IotaKeySignature, KeyId = String>> {
        let signer = AwsKmsStorage::get_signer(self, key_id)?;
        Ok(signer)
    }
}

// Similar to IotaSigner, currently copy of other signing fn, as information from AWS is not available anymore
// after converting it to AwsKeySignatureScheme PublicKey
// TODO: decide wether to keep other signature in support and refactor pub key retrieval functions
// to retrieve with optional conversion.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl KeyGet<IotaKeySignature, String> for AwsKmsStorage {
    async fn public_key(
        &self,
        key_id: &String,
    ) -> Result<<IotaKeySignature as SecretStorageSignatureScheme>::PublicKey> {
        let (public_key_der, key_spec) = get_public_key_der(&self.client, key_id).await.unwrap();
        let pk_iota = convert_public_key_der_to_iota_public_key(
            &public_key_der,
            &key_spec.try_into().unwrap(),
        )
        .unwrap();

        Ok(pk_iota)
    }
}
