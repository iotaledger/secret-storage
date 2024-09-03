use async_trait::async_trait;

use crate::Result;
use crate::SignatureScheme;

/// [`Signer`] trait is a trait that is used to sign a hash with a private key located in a key store.
/// The method is key-type agnostic, meaning that it can be used to sign a hash with any key type. The key-type is defined by the KeySignatureSet trait.
/// The purpose of this trait is to allow for more flexibility in the implementation of the key storage and avoid unnecessary dependencies and hidden functionalities.
///
/// In simple cases user may wish to not use the full key storage functionality and only sign data. In such cases, the Signer trait can be used.
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait Signer<K: SignatureScheme> {
    type KeyId;
    async fn sign(&self, data: &[u8]) -> Result<K::Signature>;
    async fn public_key(&self) -> Result<K::PublicKey>;
    fn key_id(&self) -> &Self::KeyId;
}
