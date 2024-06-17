use crate::key_signature_set::KeySignatureSet;

pub trait Signer<K: KeySignatureSet> {
    async fn sign(&self, hash: impl AsRef<[u8]>) -> Result<K::Signature, anyhow::Error>;
}
