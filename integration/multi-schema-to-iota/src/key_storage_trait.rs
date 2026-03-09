// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use iota_interaction::IotaKeySignature;
use iota_interaction::OptionalSync;
use multi_schema::KeyIdDefinition;
use multi_schema::SignatureSchemeMulti;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySignWithOptions;
use secret_storage::Result;
use secret_storage::SignatureScheme as SecretStorageSignatureScheme;
use secret_storage::Signer;

use crate::signer::IotaCompatibleSigner;
use crate::storage::IotaCompatibleKeyStorage;
use crate::utils::convert_public_key_der_to_iota_public_key;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> KeyGenerate<IotaKeySignature, String> for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyGenerate<SignatureSchemeMulti, TInner::KeyId> + KeyIdDefinition + OptionalSync,
{
    type Options = TInner::Options;

    async fn generate_key_with_options(
        &self,
        options: Self::Options,
    ) -> Result<(
        String,
        <IotaKeySignature as SecretStorageSignatureScheme>::PublicKey,
    )> {
        let (key_id, public_key_multi) =
            self.inner.generate_key_with_options(options).await.unwrap();

        let public_key_iota = convert_public_key_der_to_iota_public_key(
            &public_key_multi.bytes,
            &public_key_multi.key_type,
        )
        .unwrap();

        Ok((key_id.into(), public_key_iota))
    }
}

impl<TInner> KeySignWithOptions<IotaKeySignature, String> for IotaCompatibleKeyStorage<TInner>
where
    TInner:
        KeySignWithOptions<SignatureSchemeMulti, TInner::KeyId> + KeyIdDefinition + OptionalSync,
    <TInner as KeySignWithOptions<SignatureSchemeMulti, TInner::KeyId>>::Signer:
        Signer<SignatureSchemeMulti, KeyId = TInner::KeyId> + OptionalSync,
{
    type Signer = IotaCompatibleSigner<TInner::Signer>;
    type Options = TInner::Options;

    fn get_signer_with_options(
        &self,
        key_id: &String,
        options: &TInner::Options,
    ) -> Result<Self::Signer> {
        let multi_signer = self
            .inner
            .get_signer_with_options(
                &to_inner_key_id::<TInner>(key_id)?,
                options.try_into().map_err(|_| {
                    secret_storage::Error::InvalidConfig("Failed to convert.".to_string())
                })?,
            )
            .unwrap();
        let iota_signer = IotaCompatibleSigner {
            inner: multi_signer,
        };
        Ok(iota_signer)
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> KeyGet<IotaKeySignature, String> for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyGet<SignatureSchemeMulti, TInner::KeyId> + KeyIdDefinition + OptionalSync,
{
    async fn public_key(
        &self,
        key_id: &String,
    ) -> Result<<IotaKeySignature as SecretStorageSignatureScheme>::PublicKey> {
        let public_key_multi = self
            .inner
            .public_key(&to_inner_key_id::<TInner>(key_id)?)
            .await
            .unwrap();

        let public_key_iota = convert_public_key_der_to_iota_public_key(
            &public_key_multi.bytes,
            &public_key_multi.key_type.try_into().unwrap(),
        )
        .unwrap();

        Ok(public_key_iota)
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> KeyDelete<String> for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyDelete<TInner::KeyId> + KeyIdDefinition + OptionalSync,
{
    async fn delete(&self, key_id: &String) -> Result<()> {
        self.inner.delete(&to_inner_key_id::<TInner>(key_id)?).await
    }
}

/// KeyExists trait is a trait that is used to check if a key pair with given id exists in the key store.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> KeyExist<String> for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyExist<TInner::KeyId> + KeyIdDefinition + OptionalSync,
{
    async fn exist(&self, key_id: &String) -> Result<bool> {
        self.inner.exist(&to_inner_key_id::<TInner>(key_id)?).await
    }
}

fn to_inner_key_id<T>(key_id: &String) -> secret_storage::Result<T::KeyId>
where
    T: KeyIdDefinition,
{
    key_id.clone().try_into().map_err(|_| {
        secret_storage::Error::InvalidConfig("Failed to parse inner key_id from input.".to_string())
    })
}
