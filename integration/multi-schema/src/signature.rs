use crate::KeyType;

pub struct SignatureSchemeMultiSignature {
    pub bytes: Vec<u8>,
    pub key_type: KeyType,
}
