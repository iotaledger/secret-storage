// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;

use crate::signer::Signer;
use crate::{Result, Signature};

/// [`KeysStorage`] is a trait that combines all key storage traits into one.
///
/// All sub-traits combined into this trait make the full key storage functionality.
/// Although sub-traits can be used separately. For instance if your application only
/// needs to sign data, you can use only KeySign trait as required storage.
///
/// The concept ot sub-traits is to allow for more flexibility in the implementation of the key storage and avoid unnecessary dependencies and hidden functionalities.
/// The hidden functionalities can lead to unexpected behavior and security vulnerabilities.
/// The concept of sub-traits should be thought of as a way to avoid the "god object" anti-pattern.
pub trait KeysStorage<S: Signature, I>:
    KeyGenerate<S, I> + KeySign<S, I> + KeyDelete<I> + KeyExist<I>
{
}

impl<T, S, I> KeysStorage<S, I> for T
where
    T: KeyGenerate<S, I> + KeySign<S, I> + KeyDelete<I> + KeyExist<I>,
    S: Signature,
{
}

/// [`KeyGenerate`] trait is a trait that is used to generate a new key pair. Returns the key ID and the public key
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait KeyGenerate<S: Signature, I> {
    #[cfg(not(feature = "send-sync-storage"))]
    type Options: Default;
    #[cfg(feature = "send-sync-storage")]
    type Options: Default + Send;
    async fn generate_key(&self) -> Result<(I, S::VerifyingKey)> {
        self.generate_key_with_options(Self::Options::default())
            .await
    }
    async fn generate_key_with_options(&self, options: Self::Options) -> Result<(I, S::VerifyingKey)>;
}

/// KeySign trait is a trait that is used to sign a hash with a private key located in a key store. The method return a [`Signer`] object.
pub trait KeySign<S: Signature, I>: KeyGet<S, I> {
    async fn get_signer(&self, key_id: &I) -> Result<impl Signer<S>>;
}

/// KeyDelete trait is a trait that is used to delete a key pair from the key store.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait KeyDelete<I> {
    async fn delete(&self, key_id: &I) -> Result<()>;
}

/// KeyExists trait is a trait that is used to check if a key pair with given id exists in the key store.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait KeyExist<I> {
    async fn exist(&self, key_id: &I) -> Result<bool>;
}

/// KeyGet trait is a trait that is used to get a public key from the key store.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait KeyGet<S: Signature, I> {
    async fn public_key(&self, key_id: &I) -> Result<S::VerifyingKey>;
}
