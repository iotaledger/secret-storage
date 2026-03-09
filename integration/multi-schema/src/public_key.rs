use crate::KeyType;

pub struct SignatureSchemeMultiPublicKey {
    pub bytes: Vec<u8>,
    pub key_type: KeyType,
}
