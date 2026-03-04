// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use iota_interaction::IotaKeySignature;
use iota_interaction::OptionalSync;
use multi_schema::SignatureSchemeMulti;
use multi_schema::SignatureSchemeMultiSignatureType;
use secret_storage::KeyDelete;
use secret_storage::KeyExist;
use secret_storage::KeyGenerate;
use secret_storage::KeyGet;
use secret_storage::KeySign;
use secret_storage::KeySignWithAlgorithm;
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
    TInner: KeyGenerate<SignatureSchemeMulti, String>
        + KeySign<SignatureSchemeMulti, String>
        + OptionalSync,
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
            &public_key_multi.public_key_type,
        )
        .unwrap();

        Ok((key_id, public_key_iota))
    }
}

impl<TInner> KeySignWithAlgorithm<IotaKeySignature, String, SignatureSchemeMultiSignatureType>
    for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyGenerate<SignatureSchemeMulti, String>
        + KeySignWithAlgorithm<SignatureSchemeMulti, String, SignatureSchemeMultiSignatureType>
        + OptionalSync,
    <TInner as KeySignWithAlgorithm<
        SignatureSchemeMulti,
        String,
        SignatureSchemeMultiSignatureType,
    >>::Signer: Signer<SignatureSchemeMulti, KeyId = String> + OptionalSync,
{
    type Signer = IotaCompatibleSigner<TInner::Signer>;
    fn get_signer_with_algorithm(
        &self,
        key_id: &String,
        algorithm: &SignatureSchemeMultiSignatureType,
    ) -> Result<Self::Signer> {
        let multi_signer = self
            .inner
            .get_signer_with_algorithm(&key_id.to_string(), algorithm)
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
    TInner: KeyGet<SignatureSchemeMulti, String> + OptionalSync,
{
    async fn public_key(
        &self,
        key_id: &String,
    ) -> Result<<IotaKeySignature as SecretStorageSignatureScheme>::PublicKey> {
        let public_key_multi = self.inner.public_key(key_id).await.unwrap();

        let public_key_iota = convert_public_key_der_to_iota_public_key(
            &public_key_multi.bytes,
            &public_key_multi.public_key_type.try_into().unwrap(),
        )
        .unwrap();

        Ok(public_key_iota)
    }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> KeyDelete<String> for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyDelete<String> + OptionalSync,
{
    async fn delete(&self, key_id: &String) -> Result<()> {
        self.inner.delete(key_id).await
    }
}

/// KeyExists trait is a trait that is used to check if a key pair with given id exists in the key store.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl<TInner> KeyExist<String> for IotaCompatibleKeyStorage<TInner>
where
    TInner: KeyExist<String> + OptionalSync,
{
    async fn exist(&self, key_id: &String) -> Result<bool> {
        self.inner.exist(key_id).await
    }
}
