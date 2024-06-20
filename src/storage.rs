use crate::key_signature_set::KeySignatureSet;
use crate::signer::Signer;

/// KeysStorage trait is a trait that combines all key storage traits into one.
///
/// All sub-traits combined into this trait make the full key storage functionality.
/// Although sub-traits can be used separately. For instance if your application only
/// needs to sign data, you can use only KeySign trait as required storage.
///
/// The concept ot sub-traits is to allow for more flexibility in the implementation of the key storage and avoid unnecessary dependencies and hidden functionalities.
/// The hidden functionalities can lead to unexpected behavior and security vulnerabilities.
/// The concept of sub-traits should be thought of as a way to avoid the "god object" anti-pattern.
pub trait KeysStorage<K: KeySignatureSet>:
    KeyGenerate<K> + KeySign<K> + KeyDelete<K> + KeyExist<K>
{
    type KeyID;
}

/// KeyCreate trait is a trait that is used to generate a new key pair. Returns the key ID and the public key
pub trait KeyGenerate<K: KeySignatureSet> {
    type KeyID;
    async fn generate(&self) -> Result<(Self::KeyID, K::PublicKey), anyhow::Error>;
}

/// KeyCreate trait is a trait that is used to generate a new key pair. Returns the key ID and the public key
pub trait KeyCreateWithOptions<K: KeySignatureSet> {
    type KeyID;
    type Options;
    async fn generate(
        &self,
        options: Option<Self::Options>,
    ) -> Result<(Self::KeyID, K::PublicKey), anyhow::Error>;
}

/// KeySign trait is a trait that is used to sign a hash with a private key located in a key store. The method return a [`Signer`] object.
pub trait KeySign<K: KeySignatureSet> {
    type KeyID;
    fn get_signer(
        &self,
        key_id: Self::KeyID,
    ) -> Result<impl Signer<K> + Sync + Send, anyhow::Error>;
}

/// KeyDelete trait is a trait that is used to delete a key pair from the key store.
pub trait KeyDelete<K: KeySignatureSet> {
    type KeyID;
    async fn delete(&self, key_id: &Self::KeyID) -> Result<(), anyhow::Error>;
}

/// KeyExists trait is a trait that is used to check if a key pair with given id exists in the key store.
pub trait KeyExist<K: KeySignatureSet> {
    type KeyID;
    async fn exists(&self, key_id: &Self::KeyID) -> Result<bool, anyhow::Error>;
}

/// KeyGet trait is a trait that is used to get a public key from the key store.
pub trait KeyGet<K: KeySignatureSet> {
    type KeyID;
    async fn get(&self, key_id: &Self::KeyID) -> Result<K::PublicKey, anyhow::Error>;
}
