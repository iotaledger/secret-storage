use async_trait::async_trait;

use crate::key_signature_set::KeySignatureTypes;

/// Signer trait is a trait that is used to sign a hash with a private key located in a key store.
/// The method is key-type agnostic, meaning that it can be used to sign a hash with any key type. The key-type is defined by the KeySignatureSet trait.
/// The purpose of this trait is to allow for more flexibility in the implementation of the key storage and avoid unnecessary dependencies and hidden functionalities.
///
/// In simple cases user may wish to not use the full key storage functionality and only sign data. In such cases, the Signer trait can be used.
#[async_trait]
pub trait Signer<K: KeySignatureTypes>: Send + Sync {
    fn sign(&self, hash: impl AsRef<[u8]>) -> Result<K::Signature, anyhow::Error>;
}
