// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::Result;
use crate::Signature;

// /// [`Signer`] trait is a trait that is used to sign a hash with a private key located in a key store.
// /// The method is key-type agnostic, meaning that it can be used to sign a hash with any key type. The key-type is defined by the KeySignatureSet trait.
// /// The purpose of this trait is to allow for more flexibility in the implementation of the key storage and avoid unnecessary dependencies and hidden functionalities.
// ///
// /// In simple cases user may wish to not use the full key storage functionality and only sign data. In such cases, the Signer trait can be used.
// #[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
// #[cfg_attr(feature = "send-sync-storage", async_trait)]
// pub trait Signer<K: SignatureScheme> {
//     type KeyId;

//     async fn sign(&self, data: &K::Input) -> Result<K::Signature>;

//     async fn public_key(&self) -> Result<K::PublicKey>;

//     fn key_id(&self) -> Self::KeyId;
// }

pub trait Signer<S: Signature> {
    // NOTE: this implies the signer holds a public key internally
    // and hence its construction from storage must be async.
    fn public_key(&self) -> &S::VerifyingKey;
    async fn sign(&self, data: &[u8]) -> Result<S, ()>;
}

#[cfg(feature = "iota")]
pub mod iota {
    use iota_sdk::types::Address;

    /// An IOTA transaction signer.
    pub trait TransactionSigner: iota_sdk::transaction_builder::TransactionSigner {
        fn address(&self) -> Address;
    }
}
