use crate::key_signature_set::KeySignatureSet;
use crate::signer::Signer;

pub trait KeyCreate<K: KeySignatureSet> {
    type KeyID;
    async fn generate(&self) -> Result<(Self::KeyID, K::PublicKey), anyhow::Error>;
}

pub trait KeySign<K: KeySignatureSet> {
    type KeyID;
    fn signer<'a>(&'a self, key_id: &'a Self::KeyID) -> impl Signer<K> + 'a;
}

pub trait KeyDelete<K: KeySignatureSet> {
    type KeyID;
    async fn delete(&self, key_id: &Self::KeyID) -> Result<(), anyhow::Error>;
}

pub trait KeyExists<K: KeySignatureSet> {
    type KeyID;
    async fn exists(&self, key_id: &Self::KeyID) -> Result<bool, anyhow::Error>;
}

pub trait KeyGet<K: KeySignatureSet> {
    type KeyID;
    async fn get(&self, key_id: &Self::KeyID) -> Result<bool, anyhow::Error>;
}

pub trait KeysStorage<K: KeySignatureSet>:
    KeyCreate<K> + KeySign<K> + KeyDelete<K> + KeyExists<K>
{
    type KeyID;
}
